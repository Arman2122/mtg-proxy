# Configuration

`mtg-proxy` is configured by a single TOML file, passed to `mtg-proxy run` and
re-read by `mtg-proxy access`, `mtg-proxy doctor` and `mtg-proxy web-relay`. The
repository ships [`example.config.toml`](https://github.com/Arman2122/mtg-proxy/blob/main/example.config.toml),
which lists every key with inline notes. This page is the reference version of
that file, organised by section.

A real config only contains the keys you actually change. Everything else has a
default.

- [How the file is read](#-how-the-file-is-read)
- [Top-level keys](#-top-level-keys)
- [`[secrets]`](#secrets)
- [`[secret-ad-tags]`](#secret-ad-tags)
- [`[secret-limits.<name>]`](#secret-limitsname)
- [`[[listener]]`](#listener)
- [`[web]`](#-web)
- [`[network]`](#network)
- [`[domain-fronting]`](#domain-fronting)
- [`[defense]`](#-defense)
- [`[throttle]`](#throttle)
- [`[stats]`](#stats)
- [Environment overrides](#environment-overrides)
- [A complete worked example](#a-complete-worked-example)

## ⚠️ How the file is read

Two rules cause almost every configuration bug in this project.

**Unknown keys are ignored.** The parser is called without
`DisallowUnknownFields` (`internal/config/parse.go`). That is deliberate — it is
what lets a config carrying `[[listener]]` or `[web]` load on an older binary
that predates those features. The cost is that a typo, or a key in the wrong
place, produces no error at all.

**A `[table]` header captures everything written after it.** This is ordinary
TOML, but it is unforgiving here because of the rule above. Every bare top-level
key — `bind-to`, `concurrency`, `track-client-ips`, and the rest — must be
written *before* the first `[section]` or `[[section]]` header in the file.

```toml
# WRONG: concurrency is now a key inside the listener table, not a global.
[[listener]]
bind-to = "127.0.0.1:2398"
accept = ["dd"]

concurrency = 8192
```

`[[listener]]` has no `concurrency` field, so that value is silently dropped and
the proxy runs at the default 4096. The same misplacement inside `[secrets]`
fails instead, with a confusing "invalid secret" error, because `[secrets]` maps
every key it sees to a secret name.

The layout that works, and the one the codebase's own tests pin:

1. All bare top-level keys.
2. `[domain-fronting]`, `[network]`, `[network.timeout]`, `[network.keep-alive]`,
   `[defense.*]`, `[throttle]`, `[stats.*]` — in any order.
3. `[[listener]]` blocks, then `[web]`.
4. `[secret-ad-tags]`, `[secret-limits.<name>]`, and `[secrets]` **last**.

**Every boolean defaults to `false` when omitted.** There is no "unset" state for
a bool in this config: `TypeBool.Get` returns the parsed value or the fallback,
and every call site passes `false`. So `[defense.anti-replay]`,
`[defense.blocklist]` and `[stats.prometheus]` are all *off* unless you write
`enabled = true`. The shipped `example.config.toml` sets several of them to
`true`; those are the example's choices, not the defaults.

**Address keys take a literal IP.** Everything typed as `host:port` here —
`bind-to`, `api-bind-to`, `[[listener]] bind-to`, `[web] bind-to`,
`[web] backend`, `[web] stats-bind-to`, `[stats.statsd] address`,
`[stats.prometheus] bind-to` — is parsed by `TypeHostPort`, which rejects
hostnames, `localhost` and `*`. Use `0.0.0.0` for all IPv4 interfaces and `[::]`
for dual-stack. The one exception is `[web] host`, which is a bare hostname and
rejects IP literals.

## 🔑 Top-level keys

| key | type | default | meaning |
|---|---|---|---|
| `secret` | `ee…` hex or base64 | required unless `[secrets]` is set | The single-user FakeTLS secret. Legacy simple and secured modes are not supported. |
| `bind-to` | `host:port` string, or an array of them | *required* | The MTProto listener(s). Host must be a literal IP. `"[::]:3128"` for dual-stack. |
| `api-bind-to` | `host:port` | unset (API not started) | The management HTTP API. See [[Multi-User-and-API]]. |
| `api-token` | string | unset (no authentication) | Bearer token required on every API endpoint. Without it the API relies entirely on being bound to loopback. |
| `ad-tag` | 32 hex characters (16 bytes) | unset | Advertising tag from [@MTProxybot](https://t.me/MTProxybot). Routes clients via Telegram middle proxies so a sponsored channel appears. Needs a reachable public IP. |
| `public-ipv4` | IP literal | unset (detected via ifconfig.co) | This server's public IPv4. Used by `access` to build links, by `doctor` to check SNI-to-DNS match, and as the proxy's own address in the middle-proxy handshake when `ad-tag` is set. |
| `public-ipv6` | IP literal | unset (detected) | As above, for IPv6. |
| `prefer-ip` | `prefer-ipv6` \| `prefer-ipv4` \| `only-ipv6` \| `only-ipv4` | `prefer-ipv6` | Which address family to use when connecting out to Telegram. |
| `track-client-ips` | bool | `false` | Report per-user client addresses on `/stats` and `/secrets`. See the note below before enabling. |
| `usage-state-file` | path | unset (in-memory only) | JSON file where per-secret quota usage is persisted so it survives restarts. Rewritten atomically roughly every 30 seconds and on shutdown. Quota counters only — no addresses are ever written. |
| `auto-update` | bool | `false` | Fetch proxy updates from Telegram. Usually unnecessary: a list of core proxies is compiled in. |
| `proxy-protocol-listener` | bool | `false` | Expect a PROXY protocol header (v1 or v2) on **`bind-to` only**. Each `[[listener]]` carries its own separate key. |
| `allow-fallback-on-unknown-dc` | bool | `false` | When a client asks for a DC number the proxy does not know, fall back to another DC instead of rejecting. Any DC can serve any request, at some latency cost. |
| `concurrency` | integer, 1–65535 | `4096` | Maximum concurrent connections. Everything above this is dropped. |
| `tolerate-time-skewness` | duration | `3s` | How far a FakeTLS message's encrypted timestamp may be from local time before the connection is refused. This is anti-probe machinery, so widen it only if your clock is genuinely bad. |
| `debug` | bool | `false` | Drops the log level from warn to debug. The configuration dump it emits has `secret`, every `[secrets]` value and `api-token` replaced with `[redacted]`; secret *names* are kept. |
| `domain-fronting-port` | port | — | **Deprecated.** Use `[domain-fronting] port`. |
| `domain-fronting-ip` | IP literal | — | **Deprecated and ignored**, with a startup warning. Use `[domain-fronting] host`. |
| `domain-fronting-proxy-protocol` | bool | `false` | **Deprecated.** Use `[domain-fronting] proxy-protocol`. |

### About `track-client-ips`

With `track-client-ips = true`, each user in `/stats` also carries
`connected_ips` (the distinct addresses holding a live connection right now,
sorted and deduplicated) and `last_ip` (the address of the most recent admitted
connection).

```json
"alice": {
  "connections": 2,
  "connected_ips": ["198.51.100.7", "203.0.113.44"],
  "last_ip": "203.0.113.44"
}
```

It is off by default, and that default is a decision rather than caution. This is
a circumvention proxy: the people using it are frequently the reason it exists,
and an operator's answer to "who connected from where" is also the answer
available to whoever ends up with the server. `connected_ips` adds no new
retention — those addresses are already held for the life of the connection and
vanish with it — but `last_ip` outlives the connection it came from, so a
deployment that never asks for either never accumulates one. Nothing here is
written to disk in any form.

Turn it on for a specific, bounded reason (a support case, an abuse
investigation) and turn it back off. Behind a front proxy both fields report what
the PROXY header carried, which is the client's real address. See [[Security]].

### The bind-to listener is `ee`-only

`bind-to` accepts exactly one secret form: `ee` (FakeTLS). There is no key that
changes that — the policy is a compiled-in constant
(`mtglib.DefaultListenerPolicy`), and the only way to serve the `dd` or plain
forms is a separate `[[listener]]` socket. A socket that answers obfuscated2 is
fingerprintable as an MTProto proxy, so switching one on has to be an explicit
stanza rather than a one-token edit of an existing key.

A related startup check: at least one secret must carry a fronting hostname, or
`[domain-fronting] host` must be set. Otherwise the FakeTLS listener would have
no cover site to relay a failed ClientHello to, and closing instead is exactly
the distinguisher domain fronting exists to avoid.

## `[secrets]`

Multi-user mode. Each key is a user name used for per-user stats, quotas and
throttling; each value is that user's secret. Secrets may front different
hostnames from each other.

```toml
[secrets]
alice = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"
bob   = "ee0123456789abcdef0123456789abcd9573746f726167652e676f6f676c65617069732e636f6d"
```

When `[secrets]` is present it replaces the single top-level `secret`. When it is
absent, the single secret is treated internally as one named `default` — which is
the name `[secret-ad-tags]` and `[secret-limits]` must use in that case.

This table must be last in the file. See [[Multi-User-and-API]].

## `[secret-ad-tags]`

Per-secret advertising tag overrides. Each key names a secret from `[secrets]`;
each value is a 32-character hex tag. A secret listed here uses its own tag; one
that is not listed falls back to the global `ad-tag`, if any.

```toml
[secret-ad-tags]
bob = "fedcba9876543210fedcba9876543210"
```

Register each `host:port` plus secret separately with @MTProxybot to obtain a
distinct tag. Naming a secret that does not exist is a startup error, so a typo
in the name is caught rather than silently ignored.

## `[secret-limits.<name>]`

Per-secret governance: a data quota, a speed limit, an expiry deadline and an
off switch. A secret without an entry is unlimited, never expires and is
enabled.

| key | type | default | meaning |
|---|---|---|---|
| `quota` | human size (`"10GB"`, `"500MiB"`) or a bare byte count | unlimited | Maximum relayed bytes. |
| `quota-reset` | `"none"` \| `"monthly"` | `"none"` | `none` is a lifetime cap; `monthly` resets each month. |
| `speed` | rate: `"5mbit"`, `"500kbit"`, `"1MB/s"` (bits decimal, bytes base 2, `/s` optional; minimum `64kbit`) | unlimited | Sustained throughput cap for the user, every connection and door together, upload and download combined. Live on reload. See [[Limits-and-Quotas]]. |
| `expires` | RFC3339 (`"2026-12-31T00:00:00Z"`) or `YYYY-MM-DD` | never | Validity deadline. |
| `disabled` | bool | `false` | Reject the secret without removing it. |

```toml
usage-state-file = "/var/lib/mtg/usage.json"

[secret-limits.alice]
quota = "10GB"
quota-reset = "monthly"
speed = "5mbit"
expires = "2026-12-31"

[secret-limits.bob]
quota = "500MB"
```

A user who is over quota, past expiry or disabled has new connections routed
transparently to the fronting domain — exactly what a wrong secret does — so a
prober cannot tell a limited user from an invalid one. Enforcement is at
connection time: a session in progress is not cut off mid-stream by a quota
overrun, though disabling or expiring a secret does close its live connections.

Set `usage-state-file` if you use quotas; without it, usage counters reset on
every restart. Limits set through the management API are in-memory only and are
overwritten by the next `POST /reload`. See [[Limits-and-Quotas]].

## `[[listener]]`

An extra socket serving the two pre-FakeTLS secret forms: `dd` (`dd` + 32 hex)
and plain (a bare 32-hex key). This is purely additive — `bind-to` is untouched
and stays FakeTLS-only. One port never serves both entry paths, and there is no
sniffing between them.

The intended consumer is Telegram's own WEB proxy front-end
([tproxy-server](https://github.com/telegramdesktop/tproxy-server)), whose backend
address is restricted to loopback and which speaks plain obfuscated2 to it, and
mtg-proxy's own WEB relay.

| key | type | default | meaning |
|---|---|---|---|
| `bind-to` | `host:port`, literal IP | *required* | Address for this obfuscated2 listener. |
| `accept` | string array, non-empty subset of `{"dd", "plain"}` | *required* | Which secret forms this socket honours. `"ee"` is rejected here — run two sockets if you need both. `dd` honours `0xdddddddd` (padded-intermediate) only; `plain` also honours `0xeeeeeeee` and `0xefefefef`, because a bare 16-byte secret places no constraint on the client's transport. |
| `public` | bool | `false` | Required on any non-loopback `bind-to`. It is your acknowledgement that this port answers obfuscated2 in the clear and is fingerprintable as an MTProto proxy. Startup fails without it. |
| `proxy-protocol` | bool | `false` | Expect a PROXY header on **this** listener. Independent of the top-level `proxy-protocol-listener`. |
| `on-unknown-secret` | `"close"` \| `"drain"` | `"close"` | Disposal of a connection no secret matches. `drain` reads and discards under a bounded budget (8 KiB / 20 seconds) before closing, which on a public listener is less distinctive than a prompt reset. |
| `handshakes-per-ip` | integer, 1–65535 | `30` | Failed-handshake budget per client IP per second, burst 2x. Armed only when `public = true`. |

```toml
[[listener]]
bind-to = "127.0.0.1:2398"
accept = ["dd", "plain"]
```

Notes that are not obvious from the table:

- **`handshakes-per-ip` is deliberately inert on a loopback listener.** Behind a
  loopback carrier every connection presents `127.0.0.1`, so a per-IP bucket
  there is one shared bucket an attacker empties for every legitimate user — a
  self-DoS, not a defence. Leaving `public` unset is how you turn it off.
- **This listener never domain-fronts.** It does not speak TLS, so relaying a
  probe to an HTTPS cover site would pipe a TLS alert back out of a plaintext
  port. Refused connections take `on-unknown-secret` instead, and every reason
  for refusal — wrong secret, unhonoured transport, rate limit, replayed frame,
  disabled or expired user — takes the same exit, so none is distinguishable
  from the others.
- **Two sockets may not share an address.** A duplicate between `bind-to`
  entries and `[[listener]]` blocks is a startup error, because one address
  serves exactly one accept policy.
- **Secrets are not per-listener.** A secret is 16 key bytes and the same key is
  valid in all three wire forms; the prefix only tells the client how to
  connect. An existing `ee` user keeps one name, one quota bucket and one set of
  stats whichever door they arrive through.
- **A bind failure here is logged and skipped, not fatal.** Losing a loopback
  backend port must never take the public MTProto port down with it. A failure
  binding `bind-to` itself is still fatal.

`mtg-proxy access` prints a `listeners` array with a ready-to-use link per user
per accepted form; a loopback listener gets no links and says why. See
[[Connection-Types]].

## 🌐 `[web]`

The WEB proxy relay — the transport Telegram Desktop 7.1 added, where the client
loads a page from your hostname inside its own WebView and carries MTProto over a
WebSocket from there.

The relay is a **separate process of the same binary**, reading this same file:

```bash
mtg-proxy web-relay /etc/mtg-proxy/config.toml
```

The proxy ignores this table entirely, so an unusable `[web]` block cannot stop
the MTProto port. Check it on its own:

```bash
mtg-proxy web-relay --check /etc/mtg-proxy/config.toml
```

| key | type | default | meaning |
|---|---|---|---|
| `enabled` | bool | `false` | The relay refuses to start without `true`. |
| `host` | bare hostname | *required* | The name a client types, and the name its capability is derived over. No scheme, no port, no IP literal, must contain a dot. Changing it invalidates every WEB link ever issued. |
| `bind-to` | `host:port`, literal IP | *required* | Where the relay listens for the front proxy. Loopback on a host install; inside a container, `0.0.0.0` with the port unpublished. |
| `backend` | `host:port`, literal IP | *required* | Must name a `[[listener]]` above that accepts `dd`. |
| `token-key` | path | *required* | A 32-byte key file, mode 0600, from `mtg-proxy generate-web-key <path>`. |
| `cover-dir` | path | — | Serve this directory as the cover site. Exactly one of `cover-dir` / `cover-upstream` is required. Directory listings are always off. |
| `cover-upstream` | URL | — | Reverse-proxy this application as the cover site. |
| `client-ip` | `"proxy-protocol"` \| `"x-forwarded-for"` | `"proxy-protocol"` | How the relay learns the browser's address. |
| `stats-bind-to` | `host:port`, **loopback only** | unset (no stats server) | The relay's own counters. |
| `max-sessions` | integer, 1–65535 | `1024` | Concurrent carrier sessions in this process. |
| `max-streams` | integer, 1–65535 | `512` | Logical connections one session may hold. |
| `max-frame-payload` | byte size | `1mib` | Largest payload one frame may carry. May only be lowered. |
| `carrier-batch-bytes` | byte size | `2mib` | Largest encoded batch one carrier message may hold. May only be lowered. |

```toml
[[listener]]
bind-to = "127.0.0.1:2398"
accept = ["dd", "plain"]
proxy-protocol = true

[web]
enabled = true
host = "web.example.com"
bind-to = "127.0.0.1:8099"
backend = "127.0.0.1:2398"
token-key = "/etc/mtg-proxy/web.key"
cover-dir = "/srv/site"
stats-bind-to = "127.0.0.1:8100"
```

### Why these particular constraints

**`stats-bind-to` must be loopback, and the relay refuses to start otherwise.**
That socket answers, with no credential at all, how many sessions are live and
how many bytes have moved — which is precisely the traffic analysis this
transport exists to deny. An operator who typed `0.0.0.0` has published it, and a
warning line in a log is not where they would find that out. `TypeHostPort`
already rejects `localhost` (it is not an IP literal), and a name that could
resolve anywhere is refused a second time by the loopback check.

It is also a second socket rather than a path on `bind-to`, because `bind-to` is
published to the internet by the front proxy and holds one invariant: everything
arriving without a credential the relay minted is answered by the cover site, on
every path. A real endpoint there would be a fingerprint no matter how it was
gated.

```bash
curl http://127.0.0.1:8100/stats
```

`/stats` is the only path it answers, and only to `GET`.

**The cover site is required and nothing ships as a default.** The hostname must
serve a plausible website to everyone who is not a Telegram client. A starter
page many operators installed would be a better signature than anything the
protocol leaks, so you supply your own.

**PROXY protocol is read from the `[[listener]]` stanza, not from `[web]`.** The
relay sends a header only when the backend listener's own `proxy-protocol` says
`true`. Two places to say it is two places to disagree, and the disagreement is
invisible: an unexpected header is consumed as the first bytes of the client's
obfuscated handshake. If you leave it `false`, every WEB user appears to the
proxy as `127.0.0.1` — the blocklist stops matching and the per-IP limits stop
counting, with nothing in a log to say so. Telegram's own `tproxy-server` sends
no header at all, so leave it `false` if that is your relay.

**`client-ip` has no fallback to the socket's peer.** Behind a front proxy that
peer is loopback for every user alive. With `proxy-protocol` the header is
*required*: a connection without one is refused rather than silently attributed
to the loopback. `x-forwarded-for` reads the right-most entry, and only from a
loopback peer.

**A WEB-capable client refuses an `ee` secret** before it opens a socket. WEB
links use the `dd` spelling of the same 16 key bytes, which is why the backend
listener must accept `dd` and why `mtg-proxy access` prints that form for these
links. Nothing has to be re-issued; only the spelling changes.

**`max-frame-payload` and `carrier-batch-bytes` may only be lowered.** The client
has these compiled in and learns nothing from the handshake, so a larger value
breaks interop with no error anywhere. Values above the ceiling are refused at
startup.

**Reload is automatic, and limited.** The relay watches the file and applies a
changed `[secrets]` table by itself within a few seconds, swapping its profile
set atomically; `SIGHUP` applies it immediately. Any other change under `[web]`,
or to the backend listener's `proxy-protocol`, is refused whole with "restart
required" rather than half-applied. Windows has no `SIGHUP`; the watcher is the
only trigger there.

This transport has been tried end to end against Telegram Desktop 7.1.2 on
Windows, through Caddy. Other client platforms have not been through the
acceptance checklist. See [[WEB-Proxy-Setup]].

## `[network]`

| key | type | default | meaning |
|---|---|---|---|
| `dns` | URI | system resolver (with caching) | `https://1.1.1.1`, `https://cloudflare-dns.com/dns-query` (DoH), `tls://1.1.1.1` (DoT), `1.1.1.1` or `udp://1.1.1.1` (plain UDP, IP only). A path is accepted only for DoH; user info is rejected. An empty string means the default resolver. |
| `doh-ip` | IP literal | unset | **Deprecated.** `doh-ip = "1.1.1.1"` is identical to `dns = "https://1.1.1.1"`. If `dns` is set, this is ignored. |
| `proxies` | array of `socks5://` or `socks5h://` URLs | empty (direct) | Egress via SOCKS5. User and password are optional; the port defaults to 1080. One proxy is used exclusively; two or more are load-balanced. An empty string entry means plain network. |
| `tcp-not-sent-lowat` | byte size | `128kib` | `TCP_NOTSENT_LOWAT` on outbound sockets. |

`tcp-not-sent-lowat` caps how much *unsent* data the kernel buffers per outbound
socket, which applies back-pressure to the relay loop instead of letting kernel
buffers bloat. The default is biased toward interactive latency. On a high-BDP
link (fast pipe, high RTT) it can cap single-flow upload throughput at roughly
value divided by RTT — raise it to `1mib`–`4mib` if uploads feel slow. **This is
applied only on Linux and Darwin and is ignored elsewhere.** An oversized value
is refused at startup rather than wrapped, because the socket option takes a
machine word and 32-bit builds are shipped.

### `[network.timeout]`

| key | type | default | meaning |
|---|---|---|---|
| `tcp` | duration | none applied | Deadline for establishing an outbound TCP connection. |
| `http` | duration | none applied | Deadline for an internal HTTP request (public-IP lookup, blocklist download). |
| `idle` | duration | `5m` | How long the relay pumps nothing before giving up on a connection. |
| `handshake` | duration | `10s` | Deadline for completing a client handshake. |

`tcp` and `http` genuinely have no fallback: when they are absent the underlying
dialer and HTTP client get zero, which Go reads as "no deadline". The shipped
example sets `tcp = "5s"` and `http = "10s"`, and keeping those values is the
better default than omitting them.

```toml
[network.timeout]
tcp = "5s"
http = "10s"
idle = "5m"
handshake = "10s"
```

### `[network.keep-alive]`

| key | type | default | meaning |
|---|---|---|---|
| `disabled` | bool | `false` (keep-alive on) | Turn TCP keep-alive off entirely. |
| `idle` | duration | Go's default (15s) | Idle period before the first probe. |
| `interval` | duration | Go's default (15s) | Period between consecutive probes. |
| `count` | integer, 1–65535 | Go's default (9) | Missed probes before the connection is considered dead. |

Omitting `idle`, `interval` and `count` hands Go zero values, which the runtime
fills with its own defaults. The example file writes those numbers out
explicitly, which is worth copying if you want them pinned against a future Go
release changing them.

## `[domain-fronting]`

Settings for the connection to the fronting website. Usually nothing here needs
changing; it matters when mtg sits behind a load balancer or an SNI router.

| key | type | default | meaning |
|---|---|---|---|
| `host` | hostname or IP literal, no port | the secret's own hostname | Where to actually connect for fronting. The hostname from the secret is still sent as SNI. |
| `ip` | IP literal | — | **Deprecated and ignored**, with a startup warning. Use `host`. |
| `port` | port number | `443` | Port on the fronting host. |
| `proxy-protocol` | bool | `false` | Send a PROXY header to the fronting website. |

`host` accepts a hostname as well as an IP, and hostnames are resolved at dial
time, so a dual-stack record can reach the right backend family for IPv4 and
IPv6 clients. Set it when DNS resolution of the secret's hostname is blocked, or
when it loops back to this server.

Note that `proxy-protocol` here is effectively an OR of this key and the
deprecated top-level `domain-fronting-proxy-protocol`: setting either one turns
it on.

## 🛡️ `[defense]`

### `[defense.anti-replay]`

Some countries actively probe Telegram connections by replaying captured bytes.
The proxy keeps a cache of the first bytes of each connection and refuses a
repeat.

| key | type | default | meaning |
|---|---|---|---|
| `enabled` | bool | `false` | Turn the cache on. Set it to `true`; the example does. |
| `max-size` | byte size | `1mib` | Approximate cache size. Actual usage can run 10–20% over on some architectures. |
| `error-rate` | float, `0 < x < 100` | `0.001` | Target false-positive ratio of the stable Bloom filter. |

```toml
[defense.anti-replay]
enabled = true
max-size = "1mib"
error-rate = 0.001
```

A `max-size` that does not fit a machine word is refused at startup rather than
wrapped, which matters on the 32-bit builds.

### `[defense.blocklist]` and `[defense.allowlist]`

Both take the same four keys. A blocklist rejects clients from the listed
networks; an allowlist rejects everyone *not* listed. They can be combined.

| key | type | default | meaning |
|---|---|---|---|
| `enabled` | bool | `false` | Turn the list on. A disabled allowlist performs no check at all. |
| `download-concurrency` | integer, 1–65535 | `1` | Parallel downloads, to avoid hammering the list host. |
| `urls` | array of `http(s)://` URLs or **absolute** local paths | empty | FireHOL-format netsets. |
| `update-each` | duration | `6h` | Refresh interval. |

```toml
[defense.blocklist]
enabled = true
download-concurrency = 2
urls = [
    "https://iplists.firehol.org/files/firehol_level1.netset",
]
update-each = "24h"
```

A blocked client is not rejected with an error — it is routed to the fronting
domain, so it never gets a chance to reach Telegram and cannot tell it was
blocked.

Lists are populated asynchronously: at startup they are empty and fill in the
background, and an error on any single URL is ignored. If a URL is unreachable
you will not get a startup failure, so check the logs.

**A trap worth knowing about.** `firehol_level1.netset` includes bogon networks,
and therefore RFC1918 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
If you run mtg-proxy on a home or LAN network and connect from a client on the
same LAN, that client is rejected as blacklisted with no response at all. Either
disable the section, use a narrower list such as `firehol_abusers_1d`, or connect
via a public address. See [[Troubleshooting]].

### `[defense.doppelganger]`

Real websites and real applications have different traffic shapes — delay
distributions between packets differ between a video stream and a page of static
assets. The doppelganger subsystem crawls real URLs to approximate those delay
statistics and mimic them.

| key | type | default | meaning |
|---|---|---|---|
| `urls` | array of **HTTPS** URLs | empty (subsystem idle) | Pages to crawl for delay statistics. Mix light and heavy content; CDN assets are a good source. |
| `repeats-per-raid` | integer, 1–65535 | `10` | Requests made to each URL per raid. Keep it small. |
| `raid-each` | duration | `6h` | Interval between raids. A short interval produces noticeable activity for no benefit; traffic patterns do not change quickly. |
| `drs` | bool | `false` | Dynamic TLS record sizing: start with small records and ramp up. |

`drs` is off because roughly 90% of servers do not do it — nginx, Apache and the
Java stacks all use the maximum record size always. Go tools, angie and some
patched builds do ramp. Enable it only if the site you are imitating does.

## `[throttle]`

Automatic per-user connection limits. A background goroutine recomputes caps on
an interval using a fair-share algorithm: light users keep all their connections,
and the remaining budget is split equally among heavy consumers. New connections
from over-cap users are rejected; existing connections are never killed.

| key | type | default | meaning |
|---|---|---|---|
| `max-connections` | integer, 1–65535 | unset (throttle off) | Total connection budget across all users. |
| `check-interval` | duration | `5s` | How often caps are recomputed. |

```toml
[throttle]
max-connections = 5000
check-interval = "5s"
```

With a limit of 100 and users A=1, B=1, C=90, D=110: A and B stay at 1, and the
remaining budget of 98 is split so C and D are each capped at 49. Throttle state
appears in the `/stats` response. See [[Limits-and-Quotas]].

## `[stats]`

Both backends are off unless you write `enabled = true`.

### `[stats.statsd]`

| key | type | default | meaning |
|---|---|---|---|
| `enabled` | bool | `false` | |
| `address` | `host:port`, literal IP | *required when enabled* | UDP endpoint of the statsd server. |
| `metric-prefix` | string matching `^[a-z0-9]+$` | `mtg` | Prefix for emitted metric names. Note the pattern: no dots, dashes or underscores. |
| `tag-format` | `datadog` \| `influxdb` \| `graphite` | `datadog` | |

### `[stats.prometheus]`

| key | type | default | meaning |
|---|---|---|---|
| `enabled` | bool | `false` | |
| `bind-to` | `host:port`, literal IP | *required when enabled* | Where the metrics HTTP server listens. Keep it on loopback or behind your own firewall — it is unauthenticated. |
| `http-path` | string | `/` | Path prefix, normalised to a leading slash. |
| `metric-prefix` | string matching `^[a-z0-9]+$` | `mtg` | |

```toml
[stats.prometheus]
enabled = true
bind-to = "127.0.0.1:3129"
http-path = "/"
metric-prefix = "mtg"
```

Enabling either backend also switches on per-connection traffic accounting, so
byte counters become live. See [[Monitoring]].

## Environment overrides

`mtg-proxy run` overlays a few environment variables on top of the parsed file,
mirroring the official `telegrammessenger/proxy` Docker image. The environment
always wins, and it is re-applied on every config read — including a
`POST /reload` — so an env-pinned secret or tag survives a reload.

| variable | effect |
|---|---|
| `SECRET` | A full mtg secret (`ee…` hex or base64), or a bare 16-byte hex key in the official-image format, which then also needs `SECRET_HOST`. **Replaces the entire `[secrets]` set**, along with `[secret-ad-tags]` and `[secret-limits]`. |
| `SECRET_HOST` | Fronting hostname combined with a bare-key `SECRET` into a FakeTLS secret. Ignored when `SECRET` is already a full secret. |
| `TAG` | Same as `ad-tag`. An empty value clears the tag. Not persisted — supply it on every run. |
| `MTG_BIND_TO` | Comma-separated `host:port` list overriding `bind-to`. No unprefixed form. |

The `MTG_`-prefixed variants (`MTG_SECRET`, `MTG_SECRET_HOST`, `MTG_TAG`) take
precedence over the bare names, so a generic `SECRET` in a shell cannot be
captured by accident outside a container.

A bare-key `SECRET` without `SECRET_HOST` is a startup error, not a silent
failure: `bind-to` serves FakeTLS only, the environment cannot declare a
`[[listener]]`, and minting a secret nothing can accept would be worse than
refusing.

`WORKERS` and `SECRET_COUNT` from the official image are ignored with a startup
warning — one Go process already uses every core, and multiple secrets go in
`[secrets]`.

## A complete worked example

A three-user proxy on 443, with an extra loopback listener feeding the WEB relay,
quotas on two users and Prometheus metrics. Note the order: globals, then plain
tables, then `[[listener]]` and `[web]`, then the secret tables last.

```toml
# --- global keys, before any table header ---------------------------------
bind-to = "0.0.0.0:443"
api-bind-to = "127.0.0.1:9090"
api-token = "a-long-random-string"
public-ipv4 = "203.0.113.9"
usage-state-file = "/var/lib/mtg-proxy/usage.json"
concurrency = 8192
prefer-ip = "prefer-ipv6"

# --- plain tables ---------------------------------------------------------
[network.timeout]
tcp = "5s"
http = "10s"
idle = "5m"
handshake = "10s"

[defense.anti-replay]
enabled = true
max-size = "1mib"
error-rate = 0.001

[defense.blocklist]
enabled = true
download-concurrency = 2
urls = ["https://iplists.firehol.org/files/firehol_level1.netset"]
update-each = "24h"

[throttle]
max-connections = 5000
check-interval = "5s"

[stats.prometheus]
enabled = true
bind-to = "127.0.0.1:3129"
metric-prefix = "mtg"

# --- listener and web relay ----------------------------------------------
[[listener]]
bind-to = "127.0.0.1:2398"
accept = ["dd"]
proxy-protocol = true

[web]
enabled = true
host = "web.example.com"
bind-to = "127.0.0.1:8099"
backend = "127.0.0.1:2398"
token-key = "/etc/mtg-proxy/web.key"
cover-dir = "/srv/site"
stats-bind-to = "127.0.0.1:8100"

# --- secret tables, last --------------------------------------------------
[secret-limits.alice]
quota = "50GB"
quota-reset = "monthly"

[secret-limits.carol]
expires = "2026-12-31"

[secrets]
alice = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"
bob   = "ee0123456789abcdef0123456789abcd9573746f726167652e676f6f676c65617069732e636f6d"
carol = "eefedcba9876543210fedcba987654329573746f726167652e676f6f676c65617069732e636f6d"
```

Validate it before restarting anything:

```bash
mtg-proxy doctor /etc/mtg-proxy/config.toml
```

And, separately, the relay's own half:

```bash
mtg-proxy web-relay --check /etc/mtg-proxy/config.toml
```

Then print the links, including the per-listener and WEB forms:

```bash
mtg-proxy access /etc/mtg-proxy/config.toml
```

## See also

- [[Quick-Start]] for the smallest config that works
- [[Connection-Types]] for what `ee`, `dd`, plain and WEB mean on the wire
- [[WEB-Proxy-Setup]] for the front proxy and certificate
- [[Multi-User-and-API]] for `[secrets]` and the management API
- [[Limits-and-Quotas]] for `[secret-limits]` and `[throttle]`
- [[Monitoring]] for the `[stats]` backends
- [[Security]] for `track-client-ips`, `public = true` and the cover site
- [[Troubleshooting]] when a setting seems to have no effect
