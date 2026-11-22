<div align="center">

# mtg-proxy

**Ultra-high-performance, pure-Rust, Linux-native Telegram MTProto Proxy**

[![CI](https://github.com/Arman2122/mtg-proxy/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Arman2122/mtg-proxy/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Arman2122/mtg-proxy?sort=semver)](https://github.com/Arman2122/mtg-proxy/releases/latest)
[![Rust](https://img.shields.io/badge/rust-1.89%2B%20%7C%20Linux%20x86__64%20%26%20aarch64-orange)](Cargo.toml)
[![Docker](https://img.shields.io/badge/ghcr.io-linux%2Famd64%20%7C%20linux%2Farm64-2496ED?logo=docker&logoColor=white)](https://github.com/Arman2122/mtg-proxy/pkgs/container/mtg-proxy)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

*One `9.6 MiB` binary. Multi-tenant governance. Hardware VAES / SHA-NI / ARMv8 crypto. `10+ GiB/s` throughput. `4.58 KiB/conn` marginal RAM.*

[Quick Install](#quick-install) ·
[5-Minute Setup](#5-minute-first-proxy-walkthrough) ·
[Anti-DPI & Stealth](#guide-2-anti-dpi-cover-website--geo-stealth-ir-geo-db) ·
[WEB Proxy](#guide-3-telegram-web-proxy-on-port-443--cdn) ·
[Outbound Engine](#guide-4-bridge--relay--universal-plug-in-outbound-routing) ·
[Management API](#guide-6-enterprise-management-api-panels--monitoring) ·
[Benchmarks](#performance-benchmarks)

</div>

---

`mtg-proxy` is a censorship-resistant [Telegram MTProto proxy](https://core.telegram.org/mtproto) written from the ground up in **pure Rust** for Linux (`x86_64` & `aarch64`). It serves everything from a personal single-VPS proxy to multi-thousand-user, 100k+-connection fleets from a single low-RAM process — with **100% drop-in compatibility** with `v1.x` TOML configs, Penhoon panels, FakeTLS (`ee`), Obfuscated2 (`dd`/`plain`), MiddleProxy (`ad-tag`), and Telegram's WEB proxy transport.

### Why `mtg-proxy`?

| Capability | What You Get Out of the Box |
|---|---|
| **Extreme Speed & Tiny RAM** | Pinned thread-per-core Linux runtime (`SO_REUSEPORT`), single-pass fused VAES / AES-NI / ARMv8-AES crypto, `10+ GiB/s` throughput, **`4.58 KiB/conn`** marginal RAM, `0 B` idle I/O buffers. |
| **All Transports on One Port** | Serve FakeTLS (`ee`), Obfuscated2 (`dd`/`plain`), Multi-Carrier Telegram WEB Proxy (`websocket`, `ws-lanes`, `https`, `https-lanes`, `auto`), and your cover website simultaneously on **`:443`** — zero Nginx/Caddy required. |
| **Modern Anti-DPI Suite** | Live cover TLS 1.3 profiling (`scout-covers`), Post-Quantum `X25519MLKEM768` (`0x11EC`), Zero-RTT `splice(2)` domain fronting (`FrontingPool`), `unknown-sni-action`, Doppelganger DRS shaping, and `~4 ns` Geo-Stealth country allowlists (`IR-Geo-DB`). |
| **Universal Outbound Engine** | Route Telegram DC & MiddleProxy traffic out over `direct://` (`SO_BINDTODEVICE` / WireGuard `wg0` / Linux `fwmark`), **Shadowsocks AEAD-2022**, SOCKS4/5, HTTP(S) CONNECT, or zero-overhead **Unix sidecars** (Xray / sing-box / VLESS+Reality / Hysteria2 / Trojan / TUIC / Tor). |
| **4-Tier User Governance** | Lock-free GCRA speed caps, data quotas with auto-reset (`daily`/`weekly`/`monthly`), per-IP limits, CGNAT-safe per-connection speed caps, water-level fair-share, bans, kicks, and lossless `rotate-secret` with overlap. |
| **Enterprise Panel Control Plane** | 35+ Bearer-authenticated REST endpoints, `ETag`/`If-Match` optimistic locking, real-time SSE `/events`, exact-once `/accounting/checkpoint`, 3-mode persistence (`memory` / `overlay` / `toml`), Prometheus `/metrics`, and StatsD. |

---

## Architecture Overview

```mermaid
flowchart LR
    C1["Telegram Client (ee / dd / WEB)"] --> L["Linux :443 Listener (SO_REUSEPORT + BBR/FQ)"]
    P["Active Prober / Foreign Scanner"] --> L

    L --> G["Geo-Stealth DIR-24-8 + Anti-Replay"]
    G -->|"Unmatched / Foreign IP / Quota Hit"| F["Zero-RTT FrontingPool + splice(2)"]
    F --> SITE["Cover Website (Local nginx/caddy or Upstream HTTPS)"]

    G -->|"Authenticated (ee / dd / WEB)"| GOV["4-Tier Governance (Quota / GCRA Speed / IP / Bans)"]
    GOV --> RELAY["DirectRelay (Fused VAES/AES-NI CTR + 8x16 KiB writev)"]

    RELAY --> OUT["Universal Outbound Router (EWMA-RTT / Failover / Per-DC / Per-Secret)"]
    OUT --> D1["Direct / WireGuard wg0 / fwmark"]
    OUT --> D2["Shadowsocks AEAD-2022 / SOCKS5 / HTTPS"]
    OUT --> D3["Unix Sidecar (Xray / sing-box / VLESS+Reality)"]
    OUT --> D4["MiddleProxy Carriers (ad-tag)"]

    D1 --> TG["Telegram DCs"]
    D2 --> TG
    D3 --> TG
    D4 --> TG
```

---

## Quick Install

`mtg-proxy` runs natively on **Linux (`x86_64` and `aarch64`)** — bare metal, KVM/cloud VMs, and Docker/Kubernetes containers.

### Option A — One-Command Linux Install (Recommended)

Installs the latest verified GitHub release binary (`/usr/local/bin/mtg-proxy`), creates a dedicated non-root `mtg` system user, installs hardened `systemd` units, and applies Linux BBR + `fq` kernel tuning:

```bash
curl -fsSL https://raw.githubusercontent.com/Arman2122/mtg-proxy/main/deploy/scripts/install.sh | sudo bash
```

<details>
<summary>Installer options (pin version, skip systemd/sysctl, or uninstall)</summary>

```bash
# Pin a specific release tag
curl -fsSL https://raw.githubusercontent.com/Arman2122/mtg-proxy/main/deploy/scripts/install.sh \
  | sudo bash -s -- --version v2.6.0

# Binary + user only (skip systemd & sysctl, e.g. inside containers)
curl -fsSL https://raw.githubusercontent.com/Arman2122/mtg-proxy/main/deploy/scripts/install.sh \
  | sudo bash -s -- --no-systemd --no-sysctl

# Uninstall binary & systemd units (preserves /etc/mtg-proxy and /var/lib/mtg-proxy)
curl -fsSL https://raw.githubusercontent.com/Arman2122/mtg-proxy/main/deploy/scripts/install.sh \
  | sudo bash -s -- --uninstall
```

</details>

### Option B — Manual Binary Download (SHA-256 Verified, No Pipe-to-Shell)

```bash
ARCH=$(uname -m | sed 's/x86_64/linux-amd64/;s/aarch64/linux-arm64/')
TAG=$(curl -fsSL https://api.github.com/repos/Arman2122/mtg-proxy/releases/latest \
  | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)
VER="${TAG#v}"
BASE="https://github.com/Arman2122/mtg-proxy/releases/download/${TAG}"

curl -fsSLO "${BASE}/mtg-proxy-${VER}-${ARCH}.tar.gz"
curl -fsSLO "${BASE}/mtg-proxy-${VER}-checksums.txt"
grep -F "  mtg-proxy-${VER}-${ARCH}.tar.gz" "mtg-proxy-${VER}-checksums.txt" | sha256sum -c -

tar -xzf "mtg-proxy-${VER}-${ARCH}.tar.gz"
sudo install -m 0755 "mtg-proxy-${VER}-${ARCH}/mtg-proxy" /usr/local/bin/mtg-proxy
mtg-proxy --version
```

### Option C — Docker & Docker Compose

Multi-arch distroless images (`linux/amd64`, `linux/arm64`, `~20 MiB`) are published to GHCR (`ghcr.io/arman2122/mtg-proxy`).

**10-second single-user container:**

```bash
SECRET=$(openssl rand -hex 16)
docker run -d --name mtg-proxy --restart unless-stopped \
  -p 443:443 \
  -e SECRET="${SECRET}" \
  -e SECRET_HOST="example.com" \
  -e MTG_BIND_TO="0.0.0.0:443" \
  ghcr.io/arman2122/mtg-proxy:latest

# Print your ready-to-use tg:// proxy link
docker exec mtg-proxy /usr/local/bin/mtg-proxy access /config/config.toml
```

**Production `docker-compose.yml` (non-root hardened + persistent config & usage state):**

```yaml
services:
  mtg-proxy:
    image: ghcr.io/arman2122/mtg-proxy:latest
    container_name: mtg-proxy
    restart: unless-stopped
    user: "65534:65534"
    read_only: true
    cap_drop: ["ALL"]
    cap_add: ["NET_BIND_SERVICE"]
    security_opt:
      - no-new-privileges:true
    ports:
      - "443:443/tcp"
      # Optional: bind Management API to host loopback only
      - "127.0.0.1:9090:9090/tcp"
    volumes:
      - /etc/mtg-proxy/config.toml:/config/config.toml:ro
      - mtg-state:/var/lib/mtg-proxy
    # Pass --epoll if your container runtime blocks io_uring_setup via seccomp:
    # command: ["run", "--epoll", "/config/config.toml"]

volumes:
  mtg-state:
```

> **Tip:** Make sure mounted `/etc/mtg-proxy/config.toml` is readable by uid `65534` (`chmod 0644` or `chown 65534:65534`), and ensure `/var/lib/mtg-proxy` is writable by uid `65534` when using `usage-state-file` or `cache-file`.

### Option D — Build from Source (Linux, Rust 1.89+)

```bash
git clone https://github.com/Arman2122/mtg-proxy.git
cd mtg-proxy
cargo build --release --locked --bin mtg-proxy
sudo install -m 0755 target/release/mtg-proxy /usr/local/bin/mtg-proxy
```

---

## 5-Minute First Proxy Walkthrough

After installing `/usr/local/bin/mtg-proxy` (Option A or B above), go from zero to a live production proxy in five commands:

### 1. Generate a FakeTLS (`ee`) secret

Use **your own domain** (best stealth) or any real, reachable TLS 1.3 hostname:

```bash
mtg-proxy generate-secret --hex example.com
# Example output:
# ee367a189aee18fa31c190054efd4a8e956578616d706c652e636f6d
```

### 2. Create `/etc/mtg-proxy/config.toml`

```bash
sudo tee /etc/mtg-proxy/config.toml >/dev/null <<'EOF'
bind-to = "0.0.0.0:443"
prefer-ip = "only-ipv4"            # Or "prefer-ipv4" / "prefer-ipv6"
tolerate-time-skewness = "120s"
usage-state-file = "/var/lib/mtg-proxy/usage.json"

# Loopback-only Management API (protected by Bearer token)
api-bind-to = "127.0.0.1:9090"
api-token = "replace-with-openssl-rand-hex-32"

[limits]
max-connections-per-ip = 128
max-new-connections-per-ip = 60

[throttle]
max-connections = 10000

[defense.anti-replay]
enabled = true
max-size = "8mib"

[defense.doppelganger]
scout-covers = true
pq-key-share = true

# IMPORTANT: [secrets] must come AFTER all top-level keys (TOML table scoping)
[secrets]
alice = "ee367a189aee18fa31c190054efd4a8e956578616d706c652e636f6d"
EOF

sudo chown root:mtg /etc/mtg-proxy/config.toml
sudo chmod 0640 /etc/mtg-proxy/config.toml
```

### 3. Validate & run diagnostics

```bash
sudo mtg-proxy run --check /etc/mtg-proxy/config.toml
sudo mtg-proxy doctor /etc/mtg-proxy/config.toml
```

`doctor` verifies config syntax, CPU hardware crypto (`VAES`/`AES-NI`/`SHA-NI`/`ARMv8`), `io_uring`, `BBR`, NTP clock drift, fronting reachability, self-loop protection, and live Telegram DC RPC handshakes.

### 4. Start on boot (and open port 443 in your firewall)

```bash
sudo systemctl enable --now mtg-proxy
sudo systemctl status mtg-proxy --no-pager
```

### 5. Print your ready-to-share Telegram links & QR URLs

```bash
sudo mtg-proxy access /etc/mtg-proxy/config.toml
```

Whenever you edit `/etc/mtg-proxy/config.toml` later, reload live with **zero disconnects**:

```bash
sudo mtg-proxy run --check /etc/mtg-proxy/config.toml && sudo systemctl reload mtg-proxy
```

---

## Step-by-Step Setup Guides

### Guide 1: Multi-User Governance, Quotas, Speed Limits & Secret Rotation

`mtg-proxy` enforces lock-free GCRA speed shaping and byte quotas across **four tiers** (server-wide, default-secret template, per-secret, and CGNAT-safe per-connection) — all hot-reloadable via `SIGHUP` or the Management API without dropping active connections:

```toml
usage-state-file = "/var/lib/mtg-proxy/usage.json"
concurrency = 32768                     # Global hard TCP connection ceiling

# Optional: Telegram sponsored channel tag (register bare 32-hex key with @MTProxybot)
# ad-tag = "0123456789abcdef0123456789abcdef"
# public-ipv4 = "203.0.113.10"

[limits]
speed = "800mbit"                       # Server-wide combined bandwidth cap
speed-up = "400mbit"                    # Server-wide upload cap
speed-down = "800mbit"                  # Server-wide download cap
quota = "950GB"                         # Monthly VPS bandwidth ceiling (0 = unlimited)
quota-reset = "monthly"                 # "none" | "daily" | "weekly" | "monthly"
max-connections-per-ip = 64             # Global concurrent connections per IPv4 or IPv6 /64
max-new-connections-per-ip = 25         # Connect-rate flood shield (conns/sec, burst 2x)
conn-speed-up = "2mbit"                 # CGNAT-safe per-connection upload cap
conn-speed-down = "8mbit"               # CGNAT-safe per-connection download cap

# Defaults inherited by EVERY secret unless overridden below
[limits.default-secret]
client-conns = 16
client-speed-up = "2mbit"
client-speed-down = "10mbit"

[throttle]
max-connections = 5000                  # Fair-share connection throttling across heavy users
check-interval = "5s"

[secrets]
alice  = "ee367a189aee18fa31c190054efd4a8e956578616d706c652e636f6d"
shared = "ee0123456789abcdef0123456789abcd956578616d706c652e636f6d"

[secret-limits.alice]
quota = "50GB"                          # Cuts off live streams at ceiling & fronts new attempts
quota-reset = "monthly"
max-connections = 32                    # Hard cap across all IPs for this user
speed = "10mbit"                        # Combined sustained cap
speed-up = "4mbit"                      # Optional directional overrides
speed-down = "10mbit"
ip-limit = 2                            # Max simultaneous devices/locations (IPv4 or IPv6 /64)
expires = "2027-01-01"                  # YYYY-MM-DD or RFC3339
disabled = false

[secret-limits.shared]
speed = "50mbit"
ip-limit = 30
client-conns = 16                       # Max simultaneous connections per IP inside shared secret
client-speed = "10mbit"                 # Static per-IP ceiling
client-fair = true                      # 1-second water-level fair-share across active IPs
```

**Rotate a leaked secret with zero downtime (keeps old key valid during overlap):**

```bash
# Generate a new key for alice, accept the old key for 24h, and live-reload via API
sudo mtg-proxy rotate-secret /etc/mtg-proxy/config.toml alice --overlap 24h --reload

# End overlap early or prune expired [[retiring-secret]] blocks
sudo mtg-proxy rotate-secret /etc/mtg-proxy/config.toml alice --end-overlap --reload
sudo mtg-proxy rotate-secret /etc/mtg-proxy/config.toml --prune --reload
```

---

### Guide 2: Anti-DPI, Cover Website & Geo-Stealth (`IR-Geo-DB`)

For regions with aggressive stateful DPI (such as Iranian mobile ISPs), **pointing your own domain to your server and fronting to a real local HTTPS cover website** eliminates SNI-vs-IP mismatches and passes active probing cleanly:

1. Point your domain (`your-site.com`) `A` record to your server IP.
2. Run a real static HTTPS website (Caddy or Nginx with a valid Let's Encrypt TLS 1.3 cert) listening on **`127.0.0.1:8443`** (see [contrib/cover-site/README.md](contrib/cover-site/README.md) for ready-made Caddy templates).
3. Generate your secret using `your-site.com` (`mtg-proxy generate-secret --hex your-site.com`) and configure `mtg-proxy`:

```toml
bind-to = "0.0.0.0:443"
bind-to-accept = ["ee"]
prefer-ip = "only-ipv4"
tolerate-time-skewness = "300s"

# Forward all unmatched probes & foreign IPs via zero-copy splice(2) to your local HTTPS site
[domain-fronting]
host = "your-site.com"
ip = "127.0.0.1"
port = 8443
unknown-sni-action = "reject-handshake"  # Sends authentic nginx TLS alert 112 for wrong SNIs

[defense.doppelganger]
scout-covers = true                      # Calibrates ServerHello & cert-flight sizes from live cover
pq-key-share = true                      # Set false if your local nginx/caddy does not negotiate ML-KEM768
server-hello-fragment-mss = "off"        # "off" matches real 3-segment TLS 1.3; use "balanced"/"tspu" only for stateless DPI
# Optional post-handshake record-size & burst shaping (0 latency after initial ramp):
# enabled = true
# drs = true
# shaping = "burst"
# server-hello-delay-min-ms = 5
# server-hello-delay-max-ms = 25

[defense.anti-replay]
enabled = true
max-size = "8mib"
error-rate = 0.0001

# Geo-Stealth Country Allowlist:
# ONLY IPs from the allowlist can authenticate to Telegram (~4 ns DIR-24-8 lookup).
# Every foreign IP / scanner / prober is transparently spliced to your cover website with 0 HMAC CPU —
# even if they possess a valid leaked secret!
[defense.allowlist]
enabled = true
action = "front"
urls = [
  "https://github.com/Arman2122/IR-Geo-DB/releases/latest/download/ir-ipv4.txt",
  # Uncomment for dual-stack:
  # "https://github.com/Arman2122/IR-Geo-DB/releases/latest/download/ir-ipv6.txt",
]
cidrs = ["127.0.0.1/32"]
cache-file = "/var/lib/mtg-proxy/ir-allowlist.cache"
update-each = "6h"
download-concurrency = 4

# Faster dead-flow recovery on mobile CGNAT/DPI blackholes (TCP_USER_TIMEOUT = 35s)
[network.keep-alive]
idle = "20s"
interval = "5s"
count = 3

[secrets]
main = "ee<32-hex-key><hex-encoded-your-site.com>"
```

> **Practical Anti-DPI Tip:** Avoid spoofing high-profile domains like `www.google.com` on well-known cloud VPS IPs (e.g., DigitalOcean/Hetzner/Vultr) — stateful mobile ISP DPI often flags SNI-vs-ASN mismatches and silently drops flows after the handshake. Always prefer **your own domain + local HTTPS cover site**, or pair with **Guide 3 (WEB Proxy + CDN)** or **Guide 4 (Domestic Bridge → Foreign Exit)**.

---

### Guide 3: Telegram WEB Proxy on Port 443 (+ CDN)

`mtg-proxy` supports Telegram's **WEB proxy transport** across Desktop, Android, and iOS via five carriers (`websocket`, `ws-lanes`, `https` sequenced Conveyor with cellular-drop replay ring, HTTP/2 `https-lanes`, and self-healing `auto`) — **all directly inside `mtg-proxy run` on port `:443`** alongside `ee` and `dd` with zero Nginx/Caddy needed:

```bash
# 1. Generate the 32-byte WEB relay token signing key (chmod 0600)
sudo -u mtg mtg-proxy generate-web-key /etc/mtg-proxy/web.key
```

```toml
# 2. All-in-One Single-Port :443 (FakeTLS ee + Obfuscated2 dd + HTTPS WEB Relay + Cover Site)
bind-to = "0.0.0.0:443"
bind-to-accept = ["ee", "dd"]

[web]
enabled = true
integrated = true                    # Runs inside `mtg-proxy run`, auto-binds internal loopback dd backend
host = "your-site.com"
hosts = ["alt.your-site.com"]        # Optional additional vhosts
carrier = "auto"                     # "websocket" | "ws-lanes" | "https" | "https-lanes" | "auto"
lanes = 2                            # Parallel lanes for ws-lanes / https-lanes
base-path = "/api/v1"                # Stealth API path prefix
token-key = "/etc/mtg-proxy/web.key"
cover-dir = "/srv/site"              # Or: cover-upstream = "http://127.0.0.1:8080"
tls-cert = "/etc/letsencrypt/live/your-site.com/fullchain.pem"  # Native h2 + HTTP/1.1 ALPN, SIGHUP-reloaded
tls-key  = "/etc/letsencrypt/live/your-site.com/privkey.pem"
stats-bind-to = "127.0.0.1:8100"

# Optional: Spoof-proof Geo-Stealth behind Cloudflare or ArvanCloud CDN
# Automatically fetches official CDN CIDRs and ONLY trusts CF-Connecting-IP / Ar-Real-IP
# when the TCP peer is proven to be a genuine CDN edge IP!
# cdn = "cloudflare"                 # "cloudflare" | "arvancloud"

[secrets]
alice = "ee367a189aee18fa31c190054efd4a8e95796f75722d736974652e636f6d"
```

Run `sudo mtg-proxy access /etc/mtg-proxy/config.toml` to print both `tg://proxy` (`ee`) and `tg://webproxy` links for every user. For standalone `mtg-proxy web-relay` deployments behind Caddy or Nginx, see [contrib/web-relay/README.md](contrib/web-relay/README.md).

---

### Guide 4: Bridge / Relay & Universal Plug-In Outbound Routing

Route outbound Telegram DC and MiddleProxy (`ad-tag`) traffic over **any protocol** — ideal for **domestic bridge → foreign exit** setups (where users connect via native `ee` `tg://proxy` to a low-latency domestic VPS, and `mtg-proxy` tunnels traffic cleanly abroad):

```toml
# 1. Kernel line-rate WireGuard / Tailscale / sing-box TUN / secondary NIC
[[outbound]]
name = "wg-eu"
url = "direct://"
interface = "wg0"                # Linux SO_BINDTODEVICE
fwmark = 0x100                   # Linux SO_MARK policy routing mark

# 2. Hardware-accelerated Shadowsocks AEAD-2022 (SIP022) or Classic AEAD
[[outbound]]
name = "ss-frankfurt"
url = "ss://2022-blake3-aes-256-gcm:<base64-32-byte-psk>@198.51.100.10:8388"

# 3. Zero-TCP-overhead Unix Domain Socket sidecar (Xray / sing-box / VLESS+Reality / Hysteria2 / Trojan / TUIC / Tor)
[[outbound]]
name = "xray-reality"
url = "unix+socks5:///run/xray/socks.sock"

# Also supported: socks5://, socks5h://, socks4://, socks4a://, http://, https:// (TLS 1.3 CONNECT), unix://, unix+http://

# Load-balancing & automatic circuit-breaker failover group
[[outbound-group]]
name = "eu-egress"
strategy = "failover"            # "ewma-rtt" | "failover" | "weighted" | "round-robin" | "hash-dc"
members = ["wg-eu", "ss-frankfurt", "xray-reality", "direct"]

[routing]
default-outbound = "eu-egress"

# Optional per-Telegram-DC outbound overrides
[routing.dc]
2 = "wg-eu"
4 = "ss-frankfurt"

# Optional per-user outbound override
[secret-limits.vip]
outbound = "xray-reality"
```

Hot-swap outbounds and routing rules at runtime with zero dropped connections via `PUT /outbounds`, and probe live DC RTT through any outbound via `POST /outbounds/{name}/probe`.

---

### Guide 5: Production Linux Kernel Tuning (`BBR` + `fq` + `systemd`)

Ready-to-deploy production templates live in `deploy/`:

- [deploy/sysctl.d/99-mtg-proxy.conf](deploy/sysctl.d/99-mtg-proxy.conf) — `fq` + `bbr`, `tcp_ecn = 0`, 65,535 listen/SYN backlogs, 16 MiB TCP buffer auto-tuning, `tcp_mtu_probing = 1`, `tcp_fastopen = 3`, `tcp_notsent_lowat = 16384`, `fs.file-max = 2097152`.
- [deploy/systemd/mtg-proxy.service](deploy/systemd/mtg-proxy.service) — least-privilege hardened unit (`User=mtg`, `CAP_NET_BIND_SERVICE` only, `ProtectSystem=strict`, `MemoryDenyWriteExecute=yes`, `LimitNOFILE=1048576`, `ExecReload=/bin/kill -HUP $MAINPID`).
- [deploy/systemd/mtg-web-relay.service](deploy/systemd/mtg-web-relay.service) — dedicated hardened unit for standalone `web-relay`.
- [deploy/scripts/bootstrap-ubuntu.sh](deploy/scripts/bootstrap-ubuntu.sh) — full Ubuntu 24.04 LTS host bootstrapper (NTP `chrony`, SSH key-only hardening, sysctl, verified binary, systemd).
- [deploy/scripts/deploy-release.sh](deploy/scripts/deploy-release.sh) — zero-downtime atomic SSH release deployer with automatic health-check rollback.

> **Important Linux BBR Gotcha:** `net.core.default_qdisc = fq` in `sysctl` only applies to *newly created* interfaces. On an already-running server, activate `fq` immediately on your primary NIC so BBR gets kernel packet pacing instead of falling back to `fq_codel`:
>
> ```bash
> IFACE=$(ip route show default | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
> sudo tc qdisc replace dev "$IFACE" root fq
> tc qdisc show dev "$IFACE"   # should show: qdisc fq ...
> ```
> *(Our `install.sh` and `bootstrap-ubuntu.sh` scripts do this automatically.)*

---

### Guide 6: Enterprise Management API, Panels & Monitoring

Enable the HTTP Management API with Bearer auth and choose your runtime persistence mode:

```toml
api-bind-to = "127.0.0.1:9090"
api-token = "replace-with-strong-random-token"
track-client-ips = false             # Privacy default: client IPs omitted & never written to disk

[api]
# "memory"  (default) - zero disk writes; ideal when an external VPN panel DB owns state (PUT /state)
# "overlay"           - crash-safe atomic 0600 SHA-256 JSON overlay (flock + fsync + rename); keeps config.toml GitOps-clean
# "toml"              - lossless toml_edit writeback directly into config.toml (preserving comments)
persistence = "overlay"
state-file = "/var/lib/mtg-proxy/runtime-state.json"

[stats.prometheus]
enabled = true
bind-to = "127.0.0.1:3129"
http-path = "/metrics"
metric-prefix = "mtg"
```

**Quick API examples:**

```bash
AUTH="Authorization: Bearer replace-with-strong-random-token"

# Liveness, live stats & panel capabilities
curl -s -H "$AUTH" http://127.0.0.1:9090/healthz
curl -s -H "$AUTH" http://127.0.0.1:9090/stats
curl -s -H "$AUTH" http://127.0.0.1:9090/capabilities

# Add a user live with 50 GB monthly quota and 10 Mbit/s speed cap
curl -s -X POST -H "$AUTH" -H "Content-Type: application/json" \
  http://127.0.0.1:9090/secrets \
  -d '{"name":"bob","secret":"ee0123456789abcdef0123456789abcd6578616d706c652e636f6d","quota":"50GB","quota_reset":"monthly","speed":"10mbit","ip_limit":2}'

# Top up a user's quota atomically (+20 GB) without resending their key
curl -s -X PATCH -H "$AUTH" -H "Content-Type: application/json" \
  http://127.0.0.1:9090/secrets/bob \
  -d '{"add_quota":"20GB"}'

# Stream real-time mutation events (SSE, zero polling)
curl -N -H "$AUTH" http://127.0.0.1:9090/events
```

Every response includes strong `ETag: "rev-N"` and `X-State-Revision: N`. Pass `If-Match: "rev-N"` on mutations for optimistic concurrency control (`412 Precondition Failed` on stale revisions).

<details>
<summary><strong>Full Management HTTP API Reference (35+ Endpoints)</strong></summary>

| Category | Method & Path | Description |
|---|---|---|
| **Core & Panel Discovery** | `GET /healthz` | Lightweight liveness/readiness probe (uptime, connections, active secrets, IP filters). |
| | `GET /capabilities` | Multi-core panel discovery (`protocol`, `transports`, `outbound_protocols`, `persistence`, `boot_id`, `state_revision`, `features`). |
| | `GET /state` / `PUT /state` | Export or atomically converge full mutable state (secrets, limits, ad-tags, outbounds, routing) in one call. |
| | `GET /events` | Real-time Server-Sent Events (`text/event-stream`) stream of live control-plane changes. |
| | `POST /reload` | Full async hot-reload of `config.toml` (secrets, limits, ad-tags, throttle, fronting, allowlist/blocklist). |
| **Accounting & Stats** | `GET /stats` | Global & per-user counters, `listeners`, `obfuscated`, `faketls_handshake`, and `throttle` status. |
| | `GET /accounting` | Multi-tenant billing ledger (`bytes_in`, `bytes_out`, `total_connections`, `quota_used`/`remaining`, `quota_cutoffs`, `last_seen`). |
| | `POST /accounting/flush` | Immediate crash-safe atomic flush of `usage-state-file` to disk. |
| | `POST /accounting/checkpoint` | Exact-once per-consumer distributed billing deltas (`boot_id`, `sequence`, `peek`, `counter_reset`). |
| **Secrets CRUD** | `GET /secrets` | List all secrets with mode, host, effective ad-tag, limits, retiring info, and live usage. |
| | `GET /secrets/{name}` | Inspect one named secret (`404` if missing). |
| | `POST /secrets` | Add or update one secret (key, optional `ad_tag`, and governance limits). |
| | `PATCH /secrets/{name}` | Partial atomic account update (`add_quota`, `reset_quota`, `disabled`, `expires`, `max_connections`, speed/IP limits). |
| | `PUT /secrets` | Atomically replace the entire secret set while preserving active retiring keys of retained names. |
| | `POST /secrets/batch` | Atomic bulk `upsert` + `delete` in a single lock-free `ArcSwap` swap. |
| | `DELETE /secrets/{name}` | Delete one secret (`409` if it is the last remaining secret). |
| **Session & Abuse Control** | `POST /secrets/{name}/reset-quota` | Zero a secret's `quota_used` counter and restart its quota period. |
| | `POST /secrets/{name}/disconnect` | Immediately disconnect all active streams for a secret without banning. |
| | `POST /secrets/{name}/kick` | Immediately close active streams matching specified `{"ips":[...]}` (`O(K)` indexed). |
| | `GET /secrets/{name}/clients?limit=N` | Per-address usage sorted by bytes moved (default 100, max 1,000; IPs shown only if `track-client-ips = true`). |
| | `GET/PUT/DELETE /secrets/{name}/external-ips` | View, report (`{"ips":[...],"ttl":"90s"}`), or clear external cluster IPs counted toward `ip-limit`. |
| | `POST/GET /secrets/{name}/bans` | Temporarily ban addresses (`{"ips":[...],"ttl":"1h","force"?}`) and kick live streams. |
| | `DELETE /secrets/{name}/bans/{address}` | Unban an IPv4 address or IPv6 `/64` prefix. |
| **Global Governance** | `GET /limits` | Inspect live server-wide `[limits]` (concurrency, global speed/quota, per-IP caps, `conn-speed`, rejections). |
| | `PUT /limits` / `PATCH /limits` | Live atomic update of server-wide `[limits]` without restarting. |
| | `POST /limits/reset-quota` | Reset the server-wide `[limits]` quota counter to zero. |
| **Outbounds & Routing** | `GET /outbounds` / `PUT /outbounds` | Inspect live RTT/dials/circuit breakers or hot-swap `[[outbound]]`, `[[outbound-group]]`, and `[routing]`. |
| | `POST /outbounds/{name}/probe` | Actively dial Telegram DC through outbound `{name}` (bypassing open circuit) and return live RTT. |
| **IP Filters & Ad-Tags** | `GET /ip-filters` | Inspect allowlist/blocklist CIDR counts, ETag/304 hits, SHA-256 hash, and refresh state. |
| | `POST /ip-filters/refresh` | Trigger synchronous conditional HTTP (`If-None-Match` / `304`) refresh of allowlist/blocklist feeds. |
| | `GET/PUT/DELETE /adtag` | Read, set (`32` hex chars), or clear the global sponsored-channel `ad_tag`. |

</details>

---

## Performance Benchmarks

Measured on Linux using `mtg-bench ab` (interleaved rounds, wire-interop verified on both binaries, identical configs):

| Workload | Legacy Go (`v1.10.0`, 15 MiB) | **Pure Rust (`v2.x`, 9.6 MiB)** | Improvement |
|---|---:|---:|---:|
| **5,000 Idle FakeTLS Conns — Total RSS** | `307.6 MiB` | **`39.8 MiB`** | **7.7× less total RAM** |
| **5,000 Idle FakeTLS Conns — Per Conn** | `58.92 KiB/conn` | **`5.38 KiB/conn`** | **10.95× less RAM/conn** |
| **Marginal RAM Slope (`2k → 5k` conns)** | `60.05 KiB/conn` | **`4.58 KiB/conn`** | **13.1× less marginal RAM** |
| **32-Stream Raw `dd` Throughput** | `4.92–5.67 GiB/s` | **`10.80–12.34 GiB/s`** | **2.0–2.2× faster** |
| **32-Stream Raw `dd` CPU / `p99.9` Tail** | `1.01 CPU-s/GB` / `39.7 ms` | **`0.50–0.54 CPU-s/GB` / `1.31–1.58 ms`** | **1.9× less CPU, up to 30× tighter tail** |
| **32-Stream FakeTLS `ee` Throughput** | `0.08–0.09 GiB/s` | **`9.68–10.70 GiB/s`** (`16 sys/MB`) | **~115× faster, 11.7× fewer syscalls** |
| **5,000-Secret FakeTLS Scan (1-core)** | `~6.5 ms` | **`357.8 µs`** (4-way SHA-NI) | **~18× faster** |
| **5,000-Secret Live Handshake Flood (`p50`)** | `3.9–6.0 ms` (`3.9k–5.5k hs/s`) | **`1.24–1.51 ms`** (peak **`9,710 hs/s`**) | **3–4× lower median latency** |

<details>
<summary><strong>Deep Systems Engineering & Workspace Layout</strong></summary>

- **Thread-per-Core Runtime:** Pinned single-threaded `LocalSet` workers respecting Linux `sched_getaffinity(0)` (Docker/Kubernetes/systemd `AllowedCPUs=`) with independent per-core `SO_REUSEPORT` listen queues.
- **Zero-Syscall Socket Inheritance:** Tunes `TCP_NODELAY`, `SO_KEEPALIVE`, `TCP_KEEP*`, `TCP_USER_TIMEOUT`, `TCP_NOTSENT_LOWAT`, `TCP_FASTOPEN`, and `TCP_CONGESTION=bbr` once on each listener before `listen(2)` — **0 `setsockopt` syscalls per accepted connection**.
- **Single-Poll `DirectRelay`:** Owns `(client, dc)` directly without `into_split()` `Arc`s, shares 1 amortized idle timer, uses zero-memmove `TlsUnframer::unframe_spans` + 128 KiB thread-local scratch (`0 B` idle buffers), batches up to `8 × 16 KiB` FakeTLS records per `writev(2)`, and locks live task frame size to **`1,776 B`** via CI guard.
- **Multi-Arch Hardware Crypto:** Fused in-place double-CTR (`x86_64` VAES+AVX2 8-block, AES-NI 4-block; `aarch64` ARMv8 AES 4-block), multi-secret FakeTLS HMAC-SHA256 (4-way SHA-NI, 8-way AVX2, ARMv8 SHA-256), and hardware SSE4.2 / ARMv8 CRC32C for MiddleProxy.
- **Allocator:** `tikv-jemallocator` configured with `percpu_arena:percpu`, 1s dirty/muzzy decay, and background threads.

```text
mtg-proxy/
├── Cargo.toml                  # 11-crate Rust 2024 workspace (fat LTO, abort, strip)
├── crates/
│   ├── mtg-core/               # Secrets, IpUnit, limits, monotonic RotationClock
│   ├── mtg-crypto/             # VAES/AES-NI/ARMv8-AES fused-CTR, SHA-NI/AVX2/ARMv8-SHA2, PQ FakeTLS
│   ├── mtg-protocol/           # TLS unframer, PROXY v1/v2, MiddleProxy RPC, Doppelganger MLE/DRS, dcprobe
│   ├── mtg-net/                # Linux sockopts, epoll/io_uring, splice(2), DoH/DoT, DC router, Universal Outbounds
│   ├── mtg-governance/         # Sharded AddressRegistry, 4-tier GCRA + fair-share, bans, anti-replay, DIR-24-8
│   ├── mtg-webrelay/           # Multi-carrier WEB proxy (WS, HTTPS Conveyor, h2), CSP bridge, CDN IP trust
│   ├── mtg-config/             # Strict TOML parser, env overlays, redaction, lossless toml_edit rotation
│   ├── mtg-engine/             # Pinned workers, DirectRelay, FrontingPool, live Doppelganger scout, metrics
│   ├── mtg-api/                # 35+ route Enterprise Management API, SSE, checkpoints, persistence, Prometheus/StatsD
│   ├── mtg-cli/                # mtg-proxy binary, tikv-jemallocator, SIGHUP reload, doctor, access, rotate-secret
│   └── mtg-bench/              # Interleaved Linux A/B benchmark & wire-interop verifier
├── deploy/                     # Installer, Ubuntu bootstrapper, atomic deployer, systemd units & sysctl.d tuning
├── contrib/                    # Ready-made Caddy/Nginx/HAProxy configs for cover sites, SNI routing & web-relay
├── fuzz/                       # 8 libFuzzer harnesses covering every untrusted parser
├── test/webbridge/             # Live Chromium Playwright harness (36 checks)
└── tests/golden/               # Byte-exact FakeTLS, obfs2, MiddleProxy, config & rotation golden fixtures
```

</details>

---

## CLI Command Reference & Environment Variables

### Commands

| Command | Description |
|---|---|
| `mtg-proxy run [--check] [--workers N] [--epoll] <config>` | Run the proxy with `SIGHUP` hot-reload and API. `--check` strictly validates config & exits; `--epoll` skips `io_uring` probing under strict seccomp. |
| `mtg-proxy simple-run <bind-to> <secret> [flags]` | Run a single-secret proxy directly from CLI flags without a config file. |
| `mtg-proxy generate-secret [--hex\|-x] [--mode ee\|dd\|plain] [hostname]` | Generate a cryptographically random secret (default base64; `-x` for hex). |
| `mtg-proxy access [--ipv4 IP] [--ipv6 IP] [--port N] [--hex] <config>` | Print `tg://` / `t.me` / `tg://webproxy` links and QR URLs as JSON. |
| `mtg-proxy doctor [--skip-native-check] <config>` | Full diagnostic check: config, CPU crypto, `io_uring`, `BBR`, SNTP clock drift, fronting, IP filters, and live Telegram DC RPC probes. |
| `mtg-proxy rotate-secret <config> [name] [flags]` | Losslessly rotate a secret with `--overlap`, `--host`, `--end-overlap`, `--prune`, `--dry-run`, `--reload`, `--force`. |
| `mtg-proxy web-relay [--check] <config>` | Run standalone WEB proxy relay with `SIGHUP` + 2-second live config watcher. |
| `mtg-proxy generate-web-key <path>` | Generate a 32-byte WEB relay token signing key (`0600`). |
| `mtg-proxy version` / `-v` / `--version` | Print version, target triple, and git revision. |

### Environment Variables

Environment variables always override the config file (and are re-applied on every reload):

| Variable | Precedence Alias | Purpose |
|---|---|---|
| `SECRET` | `MTG_SECRET` | Full secret (`ee…`/base64) or bare 16-byte hex key (paired with `SECRET_HOST`). |
| `SECRET_HOST` | `MTG_SECRET_HOST` | Fronting hostname when `SECRET` is a bare 16-byte hex key. |
| `TAG` | `MTG_TAG` | Global sponsored-channel `ad-tag` (empty string clears it). |
| `MTG_BIND_TO` | — | Comma-separated `host:port` list overriding `bind-to`. |

See [example.config.toml](example.config.toml) for every supported TOML key and default value.

---

## Verifying Releases (Supply-Chain Security)

Every tagged release publishes Linux `amd64`/`arm64` archives, SHA-256 checksums, an **SPDX 2.3 Rust Cargo SBOM**, and signed **Sigstore / in-toto build provenance attestations**:

```bash
VERSION=2.6.0
PKG="mtg-proxy-${VERSION}-linux-amd64"
BASE="https://github.com/Arman2122/mtg-proxy/releases/download/v${VERSION}"

# 1. Verify SHA-256 checksum
curl -fsSLO "${BASE}/${PKG}.tar.gz"
curl -fsSLO "${BASE}/mtg-proxy-${VERSION}-checksums.txt"
sha256sum -c --ignore-missing "mtg-proxy-${VERSION}-checksums.txt"

# 2. Verify signed Sigstore provenance attestation (release tarball)
gh attestation verify "${PKG}.tar.gz" \
  --repo Arman2122/mtg-proxy \
  --signer-workflow Arman2122/mtg-proxy/.github/workflows/release.yml

# 3. Verify signed Sigstore provenance attestation (GHCR container image)
gh attestation verify "oci://ghcr.io/arman2122/mtg-proxy:${VERSION}" \
  --repo Arman2122/mtg-proxy \
  --signer-workflow Arman2122/mtg-proxy/.github/workflows/docker-publish.yml
```

See [SECURITY.md](SECURITY.md) for the complete verification guide and threat model.

---

## Troubleshooting & Upgrading

| Symptom | Quick Check / Fix |
|---|---|
| **First-step diagnostic for any issue** | Run `sudo mtg-proxy doctor /etc/mtg-proxy/config.toml` — checks config, NTP clock skew, fronting reachability, IP filters, and live DC RPCs in ~1 second. |
| **Messages slow / stuck "Connecting" on mobile ISPs** | 1. Verify BBR + `fq` qdisc is active on your NIC (`tc qdisc show` should show `fq`, not `fq_codel`). 2. Check NTP clock drift (`chronyc tracking`). 3. Avoid `www.google.com` cover on well-known VPS ranges; use your own domain + local cover site (Guide 2), WEB Proxy + CDN (Guide 3), or a domestic bridge (Guide 4). |
| **Permission denied binding port `443`** | Run via `deploy/systemd/mtg-proxy.service` (grants `CAP_NET_BIND_SERVICE` to non-root `mtg`), or run `sudo setcap cap_net_bind_service=+ep /usr/local/bin/mtg-proxy`. |
| **Container seccomp blocks `io_uring_setup`** | Pass `--epoll` (`mtg-proxy run --epoll /config/config.toml`) to skip the startup `io_uring` probe cleanly. |
| **Upgrading from `v1.x` (Go) to `v2.x` (Rust)** | **Drop-in compatible** with `v1.x` TOML configs, `usage-state-file`, and Penhoon panels. Run `mtg-proxy run --check /etc/mtg-proxy/config.toml` before swapping binaries. Note: `v2.x` targets Linux (`x86_64` / `aarch64`) exclusively. |

---

## Documentation, Security & Contributing

- **[Full Example Config](example.config.toml)** — every configuration option documented with defaults.
- **[Changelog](CHANGELOG.md)** — full release history and upgrade notes.
- **[Wiki Documentation](https://github.com/Arman2122/mtg-proxy/wiki)** — deep guides on installation, configuration, WEB relay, monitoring, and security.
- **[Contrib Templates](contrib/)** — production Caddy, Nginx, and HAProxy recipes for cover sites, SNI routing, and standalone WEB relays.
- **[Security Policy](SECURITY.md)** — private vulnerability disclosure, attestation verification, and side-channel notes.
- **[Contributing Guide](CONTRIBUTING.md)** — build/lint/test commands, ARM64 cross-checks, Playwright bridge harness, and performance guardrails.

---

## Credits & License

`mtg-proxy` originated as a fork of [9seconds/mtg](https://github.com/9seconds/mtg) by Sergey Arkhipov and contributors, expanded with multi-tenant governance, the enterprise Management API, universal pluggable outbounds, MiddleProxy ad-tags, secret rotation, the multi-carrier WEB proxy transport, and completely re-engineered in pure Rust for v2.x.

Licensed under the [MIT License](LICENSE).
