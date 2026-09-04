# mtg-proxy

A fast, censorship-resistant [Telegram MTProto proxy](https://core.telegram.org/mtproto)
built to serve many users from one process.

Most MTProto proxies serve one secret. mtg-proxy gives every user their own named
secret, their own fronting host, their own traffic counters and their own limits,
and lets you change all of that on a running proxy without dropping a single
connection. That is what makes it usable as the engine behind a panel, and it is
equally happy running on its own from a TOML file.

It is a fork of [9seconds/mtg](https://github.com/9seconds/mtg), whose FakeTLS,
domain fronting, anti-replay and traffic-shape mimicry are what make the thing
hard to block in the first place. See [Credits](#credits).

## What it adds

- **Multiple secrets** — one named secret per user, each with its own fronting host.
- **Per-user stats** — a JSON endpoint with live connection and byte counters.
- **Management API** — add, remove, and re-key secrets and the ad-tag at runtime.
- **Hot reload** — swap the secret set from the config file without dropping users.
- **Sponsored channel (ad-tag)** — the promoted-channel feature, back again.
- **Connection throttling** — automatic fair-share per-user connection caps.
- **Per-user quotas, expiry & disable** — data caps (with optional monthly reset),
  a validity deadline, and an on/off switch, persisted across restarts.
- **WEB proxy transport** — the connection type Telegram Desktop 7.1
  added: a page on your hostname carries MTProto over a WebSocket, so a
  network in between sees a browser visiting a website.
- **Public IP override** and **Docker-style environment variables**.

Everything underneath — FakeTLS, domain fronting, the doppelganger traffic mimic,
SOCKS5 proxy chaining, IP blocklists and allowlists, Prometheus and statsd metrics
— is upstream's and behaves as upstream documents it.

## Table of contents

- [Quick start](#quick-start)
- [Verifying a download](#verifying-a-download)
- [Running with Docker](#running-with-docker)
  - [Running the container as a non-root user](#running-the-container-as-a-non-root-user)
- [Features](#features)
  - [Multiple secrets](#multiple-secrets)
  - [Per-user stats API](#per-user-stats-api)
  - [Hot secret reload](#hot-secret-reload)
  - [Secrets & ad-tag management API](#secrets--ad-tag-management-api)
  - [API authentication](#api-authentication)
  - [Sponsored channel (ad-tag)](#sponsored-channel-ad-tag)
  - [Connection throttling](#connection-throttling)
  - [Per-user quotas, expiry & disable](#per-user-quotas-expiry--disable)
  - [WEB proxy transport](#web-proxy-transport)
  - [Public IP override](#public-ip-override)
  - [Environment variables](#environment-variables)
- [Command reference](#command-reference)
- [Configuration](#configuration)
  - [Extra listeners (`[[listener]]`)](#extra-listeners-listener)
- [Credits](#credits)

## Quick start

Download a binary from [Releases](https://github.com/Arman2122/mtg-proxy/releases)
— then [verify it](#verifying-a-download), especially if you are packaging it
for other people — or build from source (requires Go 1.26+):

```console
git clone https://github.com/Arman2122/mtg-proxy.git
cd mtg-proxy
go build          # produces ./mtg-proxy
```

If you use [mise](https://mise.jdx.dev/), `mise install && mise run build` sets
up the toolchain and builds the same binary.

Generate a secret for each user. The hostname is the site you front behind: it
does not have to point at your server, but it should be a real, reachable HTTPS
site — the classic choice is a large CDN such as `storage.googleapis.com`:

```console
mtg-proxy generate-secret --hex storage.googleapis.com
```

Write a minimal config:

```toml
bind-to = "0.0.0.0:443"
api-bind-to = "127.0.0.1:9090"

[throttle]
max-connections = 5000

# [secrets] must be the LAST section in the global scope. In TOML, every key
# after a [section] header belongs to that table, so any top-level option
# placed below [secrets] would be parsed as a secret.
[secrets]
alice = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"
bob   = "ee0123456789abcdef0123456789abcd9573746f726167652e676f6f676c65617069732e636f6d"
```

Run it:

```console
mtg-proxy run /etc/mtg/config.toml
```

Then print the connection links and QR codes for your users:

```console
mtg-proxy access /etc/mtg/config.toml
```

## Verifying a download

Every release publishes, alongside the ten platform archives:

- `mtg-proxy-<version>-checksums.txt` — one SHA-256 line per asset;
- `mtg-proxy-<version>-sbom.spdx.json` — an SPDX SBOM of the module graph the
  binaries were built from;
- a signed [build provenance attestation](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds)
  covering every one of those files, including the checksums file itself.

**Checksum** — catches a truncated download, a mangled CDN object or a
mismatched version. Fetch the checksums file next to the archive and run:

```console
VERSION=1.2.3
PKG=mtg-proxy-${VERSION}-linux-amd64

curl -sfLO "https://github.com/Arman2122/mtg-proxy/releases/download/v${VERSION}/${PKG}.tar.gz"
curl -sfLO "https://github.com/Arman2122/mtg-proxy/releases/download/v${VERSION}/mtg-proxy-${VERSION}-checksums.txt"
sha256sum -c --ignore-missing "mtg-proxy-${VERSION}-checksums.txt"
```

`--ignore-missing` checks whichever listed files you actually downloaded, and
exits non-zero if none of them matched.

**Provenance** — catches a replaced asset. The checksums file is served from
the same origin as the archive, so anyone who can swap one can swap the other;
only the attestation is signed. It needs the [`gh`](https://cli.github.com) CLI
(already present on GitHub Actions runners) and no secret:

```console
gh attestation verify "${PKG}.tar.gz" \
    --repo Arman2122/mtg-proxy \
    --signer-workflow Arman2122/mtg-proxy/.github/workflows/go.yml
```

`--signer-workflow` is the part that matters: without it, any workflow in the
repository that can mint an OIDC token would satisfy the check.

The container image carries the same attestation. Verify a released tag rather
than `latest` — attestation started with the release below, so an older image
still sitting under a floating tag has none to check:

```console
gh attestation verify oci://ghcr.io/arman2122/mtg-proxy:${VERSION} \
    --repo Arman2122/mtg-proxy \
    --signer-workflow Arman2122/mtg-proxy/.github/workflows/docker-publish.yml
```

If you package mtg-proxy for others — a panel, a distribution, an installer —
please run at least the checksum, and preferably the attestation, and fail the
build when it does not match.

## Running with Docker

The image is published to the GitHub Container Registry and ships a working
default config, so it can be configured entirely from environment variables in
the style of the official `telegrammessenger/proxy` image:

```console
docker run -d --name mtg -p 443:443 \
    -e SECRET=00112233445566778899aabbccddeeff \
    -e SECRET_HOST=storage.googleapis.com \
    -e TAG=3f40462915a3e6026a4d790127b95ded \
    -e MTG_BIND_TO=0.0.0.0:443 \
    ghcr.io/arman2122/mtg-proxy:latest
```

To run with a full config file instead, mount it over the bundled default at
`/config/config.toml`:

```console
docker run -d --name mtg -p 443:443 \
    -v /etc/mtg/config.toml:/config/config.toml:ro \
    ghcr.io/arman2122/mtg-proxy:latest
```

See [Environment variables](#environment-variables) for the full list.

`:latest` tracks the newest tagged release. Every push to `main` is published
too, but only under its `sha-<commit>` tag, so `latest` never means "whatever
landed an hour ago". Pin to `:1.2.3` if you want a specific build, and verify
it with the command in [Verifying a download](#verifying-a-download).

### Running the container as a non-root user

The image runs as root, because dropping privileges by default would break two
common setups on the next `docker pull`. If neither applies to you — and for a
process parsing hostile input off port 443, it is worth checking — add
`--user 65534:65534`:

```console
docker run -d --name mtg -p 443:443 --user 65534:65534 \
    -v /etc/mtg/config.toml:/config/config.toml:ro \
    ghcr.io/arman2122/mtg-proxy:latest
```

The two things to check first:

- **The config must be readable by uid 65534.** A root-owned `0600` config —
  a reasonable thing to do with a file full of secrets — cannot be read after
  the switch, and the proxy exits at startup. `0640` with a matching group, or
  `0644` on a file whose directory is not world-traversable, both work.
- **Binding a port below 1024 inside the container.** Docker sets
  `net.ipv4.ip_unprivileged_port_start=0` in containers by default, so
  `MTG_BIND_TO=0.0.0.0:443` still works. Kubernetes and some other runtimes do
  not: there, bind a high port inside (`MTG_BIND_TO=0.0.0.0:8443`) and publish
  it as 443 outside, or set the sysctl yourself.

If you set `usage-state-file`, its directory must also be writable by uid
65534.

## Features

### Multiple secrets

Define named secrets in the config, one per user. Each name is used as the label
in per-user stats, and each secret may front behind a different hostname.

```toml
[secrets]
alice = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"
bob   = "ee0123456789abcdef0123456789abcd9573746f726167652e676f6f676c65617069732e636f6d"
```

The single-secret `secret = "..."` form from upstream still works and is treated
as one secret named `default`.

### Per-user stats API

Set `api-bind-to` to start a small HTTP server (bind it to loopback unless you
also set an [API token](#api-authentication)):

```toml
api-bind-to = "127.0.0.1:9090"
```

```console
curl http://127.0.0.1:9090/stats
```

```json
{
  "started_at": "2026-03-29T10:30:00Z",
  "uptime_seconds": 3600,
  "total_connections": 15,
  "features": ["faketls", "listeners", "quota-reset", "secret-modes", "secrets-api"],
  "listeners": [
    { "bind": "0.0.0.0:443", "accept": ["ee"], "public": true },
    { "bind": "127.0.0.1:2398", "accept": ["dd", "plain"], "public": false }
  ],
  "obfuscated": {
    "trials": 412,
    "misses": 7,
    "denied": 7,
    "draining": 0,
    "rate_limited": 0
  },
  "users": {
    "alice": {
      "connections": 8,
      "bytes_in": 1048576,
      "bytes_out": 2097152,
      "last_seen": "2026-03-29T11:25:30Z",
      "quota_used": 3145728
    }
  }
}
```

`last_seen` is `null` for a user who has never connected. The `throttle` object
is included only when [throttling](#connection-throttling) is configured, and a
user's `quota`, `quota_remaining`, `quota_reset`, `expires_at` and `disabled`
fields appear only when that user has the corresponding
[limit](#per-user-quotas-expiry--disable) set.

`listeners` and `obfuscated` appear only when at least one
[`[[listener]]`](#extra-listeners-listener) is configured — a deployment that
serves `bind-to` alone sees exactly the response it saw before. `listeners`
reports what each socket accepts; `obfuscated` counts the trial-decryption entry
(`trials` connections tried, `misses` matched by no secret, `denied` refused for
any reason, `rate_limited` turned away by the per-IP budget, and `draining` as a
live gauge of refused connections currently being drained). A user also gains
`ad_tag_skipped` once one of its ad-tagged streams took the direct path because
its transport has no middle-proxy reframer — see
[Sponsored channel](#sponsored-channel-ad-tag).

`features` is a sorted list of capability names this build supports, meant to be
read before a capability is used — it is how a panel can tell an older binary
from a newer one without parsing version strings. Names are a public contract:
existing ones are never renamed or removed, and new ones are only ever appended.

### Hot secret reload

The `api-bind-to` listener also serves a reload endpoint, so the `[secrets]` set
can change without restarting the proxy:

```console
curl -X POST http://127.0.0.1:9090/reload
```

On success it re-reads the same config file passed to `mtg-proxy run` and swaps
the secret set in atomically:

- added secrets start working immediately;
- connections whose secret was removed or re-keyed are closed;
- every other user stays connected and their stats counters carry over.

Only `[secrets]`, `ad-tag`, `[secret-ad-tags]`, and `[secret-limits]` are
hot-applied. Changing the
bind address, domain fronting, network, or throttle settings still needs a
restart.

Responses: `200 {"status":"ok"}` on success; `500` if the config cannot be read
(the current set stays active); `503` when the proxy was started without a config
file (`simple-run`); `405` for a non-POST request.

### Secrets & ad-tag management API

The same listener exposes CRUD endpoints so you can manage secrets and the ad-tag
at runtime, without editing the file or restarting:

| Method & path | Action |
|---|---|
| `GET /secrets` | List secrets (`name`, `secret`, `host`, `mode`, `ad_tag`, `effective_ad_tag`, plus `unserved` and `quota`/`quota_used`/`quota_remaining`/`expires_at`/`disabled` when set). |
| `POST /secrets` | Add or update one: `{"name","secret","ad_tag"?,"quota"?,"quota_reset"?,"expires"?,"disabled"?}`. |
| `PUT /secrets` | Replace the whole set: `{"secrets":{name:{secret,ad_tag?,quota?,quota_reset?,expires?,disabled?}},"ad_tag"?}`. |
| `DELETE /secrets/{name}` | Remove one (`404` if unknown, `409` if it is the last one). |
| `POST /secrets/{name}/reset-quota` | Zero the secret's used-bytes counter (`404` if unknown). |
| `GET /adtag` | Read the global ad-tag: `{"ad_tag":"<hex>"\|null}`. |
| `PUT /adtag` | Set the global ad-tag: `{"ad_tag":"<32 hex chars>"}`. |
| `DELETE /adtag` | Clear the global ad-tag. |

These go through the same atomic-swap machinery as `/reload`: a changed secret
key closes that user's connections, while an ad-tag-only change does not.

`mode` is the wire form the secret serialises to (`ee`, `dd` or `plain`), and
`unserved` is `true` when no configured listener honours that form — a `dd` or
`plain` secret on a proxy with no [`[[listener]]`](#extra-listeners-listener).
Such a secret is stored and valid, it just has no door; that is deliberately not
an error, so one odd client can never take an inbound offline. The request
bodies carry no mode field: the mode rides inside the secret string itself, so
these routes are unchanged.

Direct API mutations are **in-memory only** — a later `POST /reload` (or a
restart) re-reads the config file and overrides them. Treat the file as the
source of truth and the API as a live override.

### API authentication

By default the API is unauthenticated and protected only by binding to loopback.
Because it can mutate secrets, you can require a bearer token on **every**
endpoint:

```toml
api-token = "change-me"
```

```console
curl -H "Authorization: Bearer change-me" http://127.0.0.1:9090/secrets
```

Missing or wrong tokens get `401`. When `api-token` is unset, behavior is
unchanged (no auth). Always set a token if the API is reachable from anything but
localhost.

### Sponsored channel (ad-tag)

Upstream mtg v2 dropped the promoted-channel feature; mtg-proxy brings it back.
When an ad-tag is set, matching clients are routed through Telegram **middle
proxies** (the RPC protocol) instead of directly to the data centers, and your
sponsored channel appears at the top of their chat list.

```toml
ad-tag = "0123456789abcdef0123456789abcdef"
public-ipv4 = "1.2.3.4"   # this proxy's reachable public address
```

One global tag applies to every secret; you can override it per secret:

```toml
[secret-ad-tags]
bob = "fedcba9876543210fedcba9876543210"
```

**Getting a tag.** Register your proxy with [@MTProxybot](https://t.me/MTProxybot)
to obtain a 32-character hex `ad_tag`. When the bot asks for your secret, give it
the **bare 16-byte key only** — 32 hex characters, without the `ee` prefix and
without the appended hostname. For example, from the secret
`ee`**`3610182353be658466cea76f358bf9bb`**`7777772e...` you paste only
`3610182353be658466cea76f358bf9bb`. Pasting the full FakeTLS secret makes the bot
reply *"Incorrect secret value. It must contain 32 hex characters"* — that is the
bot's format requirement, not an error in your proxy.

**Requirements and behavior.**

- The middle-proxy path adds one network hop and needs a reachable **public IP**.
  On a host behind NAT or with multiple addresses, set `public-ipv4` /
  `public-ipv6` — the proxy's source address (and port) are mixed into the RPC
  key schedule, so the middle proxy must see the address you advertise. A machine
  behind a port-rewriting NAT cannot complete this handshake; run on a host with
  a real public IP (a VPS).
- If a middle proxy cannot be reached, that connection **falls back to a direct
  DC connection** (logged as a warning) so the client stays online — the sponsored
  channel just won't show for that session.
- The middle-proxy secret and address list are fetched from Telegram lazily on
  first use and refreshed hourly, so a proxy without an ad-tag never contacts
  those endpoints.

### Connection throttling

Automatic per-user connection limits protect the server from overload. A
background goroutine recomputes caps every few seconds using a fair-share
algorithm: light users keep all their connections, and the remaining budget is
split equally among heavy consumers. New connections from over-cap users are
rejected; existing connections are never killed.

```toml
[throttle]
max-connections = 5000
check-interval = "5s"
```

Example — limit 100, with users A=1, B=1, C=90, D=110: A and B stay at 1, and the
remaining budget of 98 is split so C and D are each capped at 49.

Throttle state is exposed in the stats response:

```json
{
  "throttle": {
    "active": true,
    "limit": 5000,
    "caps": { "heavy-user": 2450 }
  }
}
```

### Per-user quotas, expiry & disable

Each named secret can carry governance limits — a data quota, a validity
deadline, and an on/off switch — so you can run mtg-proxy as a reseller or
multi-tenant proxy. Add a `[secret-limits.<name>]` table for any secret in
`[secrets]`; a secret without one is unlimited, never expires and is enabled.

```toml
# Persist quota usage across restarts (optional but recommended for quotas).
usage-state-file = "/var/lib/mtg/usage.json"

[secret-limits.alice]
quota = "10GB"            # human size or a bare byte count; omit for unlimited
quota-reset = "monthly"   # "none" (default, lifetime cap) or "monthly"
expires = "2026-12-31"    # RFC3339 or YYYY-MM-DD; omit for never
disabled = false          # true rejects the secret without removing it

[secret-limits.bob]
quota = "500MB"
```

When a user is over quota, past its expiry, or disabled, new connections are
transparently routed to the **fronting domain** — exactly like a wrong secret —
so a prober cannot tell a limited user from an invalid one. Enforcement happens
at connection time: an in-progress session is not cut off mid-stream, but
disabling or expiring a secret (via reload or the API) closes its live
connections immediately. A quota overrun never kills an active session.

Usage is exposed per user in `/stats` and `/secrets`:

```json
{
  "users": {
    "alice": {
      "connections": 2,
      "bytes_in": 1048576,
      "bytes_out": 2097152,
      "quota_used": 3145728,
      "quota": 10737418240,
      "quota_remaining": 10734272512,
      "quota_reset": "monthly",
      "expires_at": "2026-12-31T00:00:00Z"
    }
  }
}
```

Set `usage-state-file` so `quota_used` survives restarts; it is flushed
atomically every ~30 seconds and on shutdown. With `quota-reset = "monthly"` the
counter resets at the start of each calendar month. Clear a user's usage
manually with `POST /secrets/{name}/reset-quota`. Limits set through the
management API are in-memory only and are overridden by the next reload — the
config file remains the source of truth.

### WEB proxy transport

Telegram Desktop 7.1 added a **WEB proxy** connection type. The client loads a
page from your hostname inside its own WebView, and that page carries an MTProto
stream over a WebSocket. On the wire it is a browser visiting a website over
ordinary HTTPS — no obfuscated2 handshake to fingerprint and no FakeTLS to
distinguish, because the TLS is real.

`mtg-proxy` serves it from a **second process of the same binary**, reading the
same configuration file:

```bash
mtg-proxy generate-web-key /etc/mtg-proxy/web.key
mtg-proxy web-relay --check /etc/mtg-proxy/config.toml   # validates and exits
mtg-proxy web-relay /etc/mtg-proxy/config.toml
```

```toml
[[listener]]
bind-to = "127.0.0.1:2398"
accept = ["dd", "plain"]
proxy-protocol = true          # carries the browser's address to the proxy

[web]
enabled = true
host = "web.example.com"       # real certificate, port 443, no IP literals
bind-to = "127.0.0.1:8099"     # where the front proxy reaches the relay
backend = "127.0.0.1:2398"     # must name the [[listener]] above
token-key = "/etc/mtg-proxy/web.key"
cover-dir = "/srv/site"        # or cover-upstream = "http://127.0.0.1:8080"
```

`mtg-proxy access` then prints a `web` object per secret. Four things are
different from every other link in this README, and all four come from the
client:

- **The secret is the `dd` form.** A WEB-capable client refuses an `ee` secret
  before it opens a socket. It is the same sixteen bytes; only the spelling
  changes, so nothing has to be re-issued.
- **There is no address and no port.** The client's form has one field, a
  hostname, and forces `https` and 443. Changing the hostname invalidates every
  WEB link ever issued, exactly like changing an `ee` secret's fronting domain.
- **A real certificate is required.** The WebView validates it normally and
  offers no way past an error, so this needs a front proxy that terminates TLS
  — Caddy in the [deployment guide](contrib/web-relay/README.md).
- **Telegram Desktop 7.1.2 or later.** Earlier 7.1 builds had a WebView2 bug
  that broke some WEB proxies on Windows.

The hostname must also serve a plausible website. Everything that arrives without
a credential the relay minted gets it — on every path, including the API ones
— and nothing ships as a default, because a starter page many operators
installed would be a better signature than anything the protocol leaks.

[contrib/web-relay/](contrib/web-relay/README.md) is the deployment: the Caddy
vhost, the four hops that have to carry the client's address, and the acceptance
checklist for a real client. `/stats` advertises `web-relay` in `features` when a
binary can serve this.

### Public IP override

Useful when automatic detection via ifconfig.co is unavailable, or when the
address the outside world sees differs from any local interface.

```toml
public-ipv4 = "1.2.3.4"
public-ipv6 = "2001:db8::1"
```

These addresses are used by `mtg-proxy access` to build links, by
`mtg-proxy doctor` to validate the SNI-to-DNS match, and — when an ad-tag is set
— as this proxy's own address in the middle-proxy handshake.

### Environment variables

For parity with the official
[telegrammessenger/proxy](https://hub.docker.com/r/telegrammessenger/proxy/)
image, `mtg-proxy run` overlays a few environment variables on top of the config
file. The environment always wins over the file, and it is re-applied on every
config read, so an env-pinned secret or tag survives a `POST /reload`.

| Variable | Meaning |
|---|---|
| `SECRET` | Proxy secret. Either a full mtg secret (`ee…` hex or base64) or a bare 16-byte hex key in the official-image format — the latter also needs `SECRET_HOST`. Replaces the whole `[secrets]` set and `[secret-ad-tags]`. |
| `SECRET_HOST` | Domain-fronting hostname combined with a bare 16-byte `SECRET` into a FakeTLS secret. Ignored when `SECRET` is already a full secret. |
| `TAG` | Advertising tag from [@MTProxybot](https://t.me/MTProxybot); same as `ad-tag` in the config. An empty value clears the tag. Like the official image, it is not persisted — provide it on every run. |
| `MTG_BIND_TO` | Comma-separated `host:port` list overriding `bind-to`. |

The `MTG_`-prefixed variants (`MTG_SECRET`, `MTG_SECRET_HOST`, `MTG_TAG`) take
precedence over the bare names, so a generic name like `SECRET` in a shell can't
be captured by accident outside a container.

`WORKERS` and `SECRET_COUNT` from the official image are not applicable — one Go
process already uses every CPU core, and multiple secrets are configured through
`[secrets]` or the API. Setting either is ignored with a startup warning.

## Command reference

| Command | Description |
|---|---|
| `mtg-proxy generate-secret [--hex] <hostname>` | Generate a new secret for the given fronting hostname. `--hex`/`-x` prints hex instead of base64. |
| `mtg-proxy run <config>` | Run the proxy from a config file (supports the full feature set and hot reload). |
| `mtg-proxy simple-run <bind-to> <secret>` | Run without a config file, from flags only (no `[secrets]`, no reload). |
| `mtg-proxy access [--ipv4 IP] [--ipv6 IP] [--port N] [--hex] <config>` | Print `tg://` / `t.me` links and QR-code URLs for the configured secrets. |
| `mtg-proxy doctor [--skip-native-check] <config>` | Check connectivity, clock skew, fronting reachability, and SNI-to-DNS match. Run this first when something is off. |
| `mtg-proxy web-relay [--check] <config>` | Run the WEB proxy relay for the secrets in a config file. `--check` validates the `[web]` table and exits. |
| `mtg-proxy generate-web-key <path>` | Write the WEB relay's 32-byte token signing key. |
| `mtg-proxy version` | Print the version. |

## Configuration

[example.config.toml](example.config.toml) documents every option with its
default value and inline notes. A real config only needs the options you actually
change — every key has a sensible default.

### Extra listeners (`[[listener]]`)

`bind-to` is, and stays, FakeTLS-only. To also serve the two pre-FakeTLS secret
forms — `dd` (`dd` + 32 hex) and plain (a bare 32-hex key) — add a `[[listener]]`
block. It is a separate socket: one port never serves both entry paths, and there
is no sniffing.

```toml
bind-to = "0.0.0.0:443"        # unchanged, FakeTLS only

[[listener]]
bind-to = "127.0.0.1:2398"
accept  = ["dd", "plain"]
```

The intended consumer is Telegram's own WEB proxy front-end
([tproxy-server](https://github.com/telegramdesktop/tproxy-server)), whose backend
address is restricted to loopback and which speaks plain obfuscated2 to it.

| key | type | default | meaning |
|---|---|---|---|
| `bind-to` | `host:port`, host must be a literal IP | *required* | address for this obfuscated2 listener |
| `accept` | string array, non-empty subset of `{"dd","plain"}` | *required* | which secret forms this socket honours. `"ee"` is rejected — run two listeners if you need both |
| `public` | bool | `false` | your acknowledgement that a non-loopback obfuscated2 port is fingerprintable as an MTProto proxy. Required on any non-loopback `bind-to` |
| `proxy-protocol` | bool | `false` | expect a PROXY header on **this** listener. The top-level `proxy-protocol-listener` applies to `bind-to` only |
| `on-unknown-secret` | `"close"` \| `"drain"` | `"close"` | disposal of a connection no secret matches. `drain` reads and discards under a bounded budget instead of resetting |
| `handshakes-per-ip` | uint | `30` | per-IP failed-handshake budget per second (burst 2×). Armed only when `public = true`, because behind a loopback carrier every connection presents `127.0.0.1` and one shared bucket is a self-DoS |

Secrets are not per-listener. A secret is 16 key bytes, and the same key is valid
in all three wire forms; the prefix only tells the *client* how to connect. So an
existing `ee` user keeps one name, one quota bucket and one set of stats whichever
door they arrive through — nothing needs to be re-issued.

> **TOML ordering.** `[[listener]]` is an array of tables, so every top-level key
> written after it belongs to the listener rather than to the global scope — the
> same rule that already forces `[secrets]` to come last. Put your `[[listener]]`
> blocks after all global keys, and `[secrets]` after those.

Older mtg-proxy binaries ignore unknown TOML keys, so a config carrying
`[[listener]]` still runs on one that predates this feature: it simply serves
`ee` on `bind-to` as before, and no user of any existing mode is affected.

## Credits

mtg-proxy is a fork of [9seconds/mtg](https://github.com/9seconds/mtg) by Sergey
Arkhipov and contributors. All of the core proxy engineering is theirs; this fork
adds the multi-user layer on top. The middle-proxy (ad-tag) implementation is
ported from the last mtg v1 release that shipped it.
