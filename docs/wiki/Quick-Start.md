# Quick Start

From an installed binary to a proxy one person can connect to, then a second
user added without restarting anything. Nothing here assumes prior knowledge of
the project — only that `mtg-proxy` is on your PATH. If it is not, start at
[[Installation]].

The commands and output below come from a real run of v1.3.0. `203.0.113.9`
stands in for your server's public address, and the secrets are throwaway keys
generated for this page.

## Before you begin

**Check the binary runs.**

```bash
mtg-proxy --version
```

It prints one line with the version, the Go toolchain, the build time and the
commit. Note the flag: `version` is not a subcommand, and `mtg-proxy version`
fails with `unexpected argument version`.

**You need a host with a public IP.** Clients connect to an address and a port,
so a machine behind NAT with no port forwarding will not work. A small VPS is
the usual answer.

**You need port 443 free.** On Linux, binding a port below 1024 requires root or
`CAP_NET_BIND_SERVICE` on the binary — standard behaviour, not something this
project changes. Any port works; 443 is the conventional choice because
outbound 443 is rarely filtered.

This page uses `/etc/mtg-proxy/config.toml` as the config path throughout.

## Step 1 — Generate a secret 🔑

One secret per user.

```bash
mtg-proxy generate-secret --hex storage.googleapis.com
```

```
eebb05691fe79c77f6bcc234f166f67f1b73746f726167652e676f6f676c65617069732e636f6d
```

The hostname argument is the site you **front behind**. The default connection
type is FakeTLS: the client opens what looks like an ordinary TLS handshake to
that name, and anything arriving on the port that does not authenticate as one
of your users is relayed to that site instead. So a prober gets a real website
back rather than a closed socket or an error.

That hostname must be a real, reachable HTTPS site. It does not have to be your
server — the classic choice is a large CDN such as `storage.googleapis.com`,
which is what the examples here use.

The hostname is not optional for this mode:

```bash
mtg-proxy generate-secret --hex
```

```
mtg-proxy: error: cannot generate a secret: mode ee requires a domain fronting hostname
```

Drop `--hex` and you get the same key in base64 instead. It is one 16-byte key
in two spellings; the config accepts either. Hex is easier to compare by eye,
base64 is what the `tg://` links carry.

Generate your own. Do not copy the secrets printed on this page — they are real
keys, and a secret anyone can read is a secret anyone can use.

## Step 2 — Write the config

```toml
bind-to = "0.0.0.0:443"
api-bind-to = "127.0.0.1:9090"

# [secrets] must be the LAST section in the file. See below.
[secrets]
alice = "eebb05691fe79c77f6bcc234f166f67f1b73746f726167652e676f6f676c65617069732e636f6d"
```

That is the whole thing. Every other option has a working default;
[example.config.toml](https://github.com/Arman2122/mtg-proxy/blob/main/example.config.toml)
documents all of them, and [[Configuration]] explains the ones you are likely to
reach for next.

- **`bind-to`** — where clients connect. The host part must be a literal IP
  address; hostnames and `*` are rejected. This socket speaks FakeTLS and only
  FakeTLS: no config key changes that. The other two connection types get their
  own sockets, which is what [[Connection-Types]] is about.
- **`api-bind-to`** — a small HTTP server used in steps 3 and 5 for `/stats` and
  `/reload`. Keep it on `127.0.0.1`. With no `api-token` set it is completely
  unauthenticated, and it can rewrite your secret set — the proxy says as much
  in its own log, `"auth":"unauthenticated"`. See [[Multi-User-and-API]] for the
  token and the rest of the endpoints.
- **`[secrets]`** — one line per user. The key is the user's name, and it is the
  label that shows up in stats, quotas and limits.

### The TOML ordering trap

In TOML, every key written after a `[section]` header belongs to that section.
`[secrets]` is a section, so any top-level option placed below it is parsed as a
secret rather than as a setting.

This config is broken:

```toml
bind-to = "0.0.0.0:443"

[secrets]
alice = "eebb05691fe79c77f6bcc234f166f67f1b73746f726167652e676f6f676c65617069732e636f6d"

api-bind-to = "127.0.0.1:9090"
```

```
mtg-proxy: error: cannot init config: cannot parse config: cannot parse a config: incorrect secret format: illegal base64 data at input byte 3
```

`api-bind-to` became a secret named `api-bind-to`, and `127.0.0.1:9090` is not a
valid secret. The loud failure is the lucky outcome: a value that happened to
parse as a secret would have been accepted, giving you a phantom user and
silently dropping the setting you meant to apply.

The same rule applies to `[secret-ad-tags]`, `[secret-limits]`, `[[listener]]`,
`[web]` and `[domain-fronting]`. Write all bare top-level keys first, then the
other tables, and put `[secrets]` last.

## Step 3 — Run it, and read the log

```bash
mtg-proxy run /etc/mtg-proxy/config.toml
```

**A healthy start prints nothing at all.** The default log level is warn, and
there is no "listening on 0.0.0.0:443" line to wait for — the process starts,
writes zero bytes to stdout, and stays quiet. That is the success case. It also
means the inverse is useful: at the default level, anything that does appear is
a warning or an error and is worth reading.

Failure is loud and immediate, so silence is not ambiguous. A port that is
already taken, or one you lack the privileges to bind, exits at once:

```
mtg-proxy: error: cannot start proxy on 0.0.0.0:443: cannot build a base listener: listen tcp 0.0.0.0:443: bind: address already in use
```

If you want to watch it come up, set `debug = true` at the top of the config for
one run. Three entries appear, as JSON:

```json
{"level":"debug","configuration":{"apiBindTo":"127.0.0.1:9090","apiToken":"[redacted]","bindTo":["0.0.0.0:443"],"debug":true,"secret":"[redacted]","secrets":{"alice":"[redacted]"},"trackClientIps":false},"logger":"","timestamp":1788549123627,"message":"configuration"}
{"level":"info","auth":"unauthenticated","bind":"127.0.0.1:9090","logger":"proxy","timestamp":1788549123627,"message":"Management API server started"}
{"level":"info","logger":"allowlist.ipblocklist.firehol","timestamp":1788549123627,"message":"ip list was updated"}
```

The real configuration dump lists every option, not the handful shown here.
Every credential in it — each secret, and `api-token` — is replaced with
`[redacted]`, so switching on debug does not copy your users' keys into a log
file that outlives the process.

Turn debug back off once you have seen it start. At debug level the proxy logs
per-connection and per-stream lines, which on a busy proxy is both a lot of disk
and a record of when individual users were active.

### Confirm it is serving

```bash
curl http://127.0.0.1:9090/stats
```

```json
{
  "started_at": "2026-09-04T22:41:33Z",
  "uptime_seconds": 6,
  "total_connections": 0,
  "features": ["client-ips", "faketls", "listeners", "quota-reset", "secret-modes", "secrets-api", "web-relay"],
  "users": {
    "alice": {
      "connections": 0,
      "bytes_in": 0,
      "bytes_out": 0,
      "last_seen": null,
      "quota_used": 0
    }
  }
}
```

The server sends this on one line; it is indented here to read. `last_seen` is
`null` until someone connects. `features` is the list of capabilities this
build supports, which is how a panel can tell one binary from another without
parsing version strings. [[Monitoring]] covers the rest of the response.

A reply to `/stats` proves the process is up and your secret parsed. Whether
Telegram is reachable from this host is a separate question:

```bash
mtg-proxy doctor /etc/mtg-proxy/config.toml
```

It prints a pass/warn/fail checklist: deprecated options, clock skew against
`tolerate-time-skewness` (3s unless you set it), connectivity to each Telegram
data centre, reachability of your fronting domain, and whether that fronting
hostname resolves to this server's public IP.

That last check reports a failure for the setup on this page, and that is
expected: `storage.googleapis.com` resolves to Google, not to you. It matters
only for the deployment shape where the fronting name is supposed to point at
your own server. [[Troubleshooting]] and [[Security]] go into what that trade-off
buys you.

## Step 4 — Hand out the connection link 🔗

```bash
mtg-proxy access /etc/mtg-proxy/config.toml
```

```json
{
  "ipv4": {
    "ip": "203.0.113.9",
    "port": 443,
    "tg_url": "tg://proxy?port=443&secret=7rsFaR_nnHf2vMI08Wb2fxtzdG9yYWdlLmdvb2dsZWFwaXMuY29t&server=203.0.113.9",
    "tg_qrcode": "https://api.qrserver.com/v1/create-qr-code?data=tg%3A%2F%2Fproxy%3Fport%3D443%26secret%3D7rsFaR_nnHf2vMI08Wb2fxtzdG9yYWdlLmdvb2dsZWFwaXMuY29t%26server%3D203.0.113.9&format=svg&qzone=4",
    "tme_url": "https://t.me/proxy?port=443&secret=7rsFaR_nnHf2vMI08Wb2fxtzdG9yYWdlLmdvb2dsZWFwaXMuY29t&server=203.0.113.9",
    "tme_qrcode": "https://api.qrserver.com/v1/create-qr-code?data=https%3A%2F%2Ft.me%2Fproxy%3Fport%3D443%26secret%3D7rsFaR_nnHf2vMI08Wb2fxtzdG9yYWdlLmdvb2dsZWFwaXMuY29t%26server%3D203.0.113.9&format=svg&qzone=4"
  },
  "secret": {
    "hex": "eebb05691fe79c77f6bcc234f166f67f1b73746f726167652e676f6f676c65617069732e636f6d",
    "base64": "7rsFaR_nnHf2vMI08Wb2fxtzdG9yYWdlLmdvb2dsZWFwaXMuY29t"
  }
}
```

Send alice `tg_url`. Opening it on a device with Telegram installed configures
the proxy in one tap. `tme_url` is the same link in a form that survives being
pasted into a chat.

Three things to know about this output.

**It calls out to the internet to learn your IP.** With no `--ipv4` flag and no
`public-ipv4` in the config, `access` fetches this host's address from
`ifconfig.co`. Pass the address to skip that:

```bash
mtg-proxy access --ipv4 203.0.113.9 /etc/mtg-proxy/config.toml
```

Setting `public-ipv4` in the config is usually better, because `doctor` and the
sponsored-channel handshake use it too.

**The secret in the link is base64, while your config holds hex.** Same sixteen
bytes. Add `-x` / `--hex` to `access` if you want the two to look alike.

**The QR codes are not generated locally.** `tg_qrcode` and `tme_qrcode` are
URLs at `api.qrserver.com` with the whole link — your server address and that
user's secret — sitting in the query string. Opening one hands that user's
credential to a third party. Render the QR code yourself if that matters to you,
which for a circumvention proxy it usually should.

The port in the link comes from the first `bind-to` address. Override it with
`-p` when the port clients reach is not the port you bind, for example behind a
NAT or a load balancer.

## Step 5 — Add a second user

Generate bob a secret the same way:

```bash
mtg-proxy generate-secret --hex storage.googleapis.com
```

Append it under `[secrets]` — which is straightforward precisely because
`[secrets]` is the last section, so there is nothing below it to displace:

```toml
[secrets]
alice = "eebb05691fe79c77f6bcc234f166f67f1b73746f726167652e676f6f676c65617069732e636f6d"
bob   = "ee9448bcbe7ec853c6d378e8995ea5408673746f726167652e676f6f676c65617069732e636f6d"
```

Tell the running proxy to re-read the file:

```bash
curl -X POST http://127.0.0.1:9090/reload
```

```json
{"status":"ok"}
```

Nobody is disconnected. The proxy re-reads the same config file it was started
with and swaps the secret set in atomically: bob works from that moment, alice
keeps her live connections and her counters carry over. Only `[secrets]`,
`ad-tag`, `[secret-ad-tags]` and `[secret-limits]` are applied this way —
changing `bind-to`, domain fronting or the network settings still needs a
restart.

Confirm:

```bash
curl http://127.0.0.1:9090/stats
```

Both users are now listed under `users`, each with their own counters.

### Getting bob's link

`access` has a limitation worth knowing before you go looking for it. It prints
one `ipv4` link block for the FakeTLS port, built from the alphabetically first
secret. With two users the output gains a `secrets` object holding each user's
key in both encodings, but no per-user `tg_url`:

```json
"secrets": {
  "alice": {
    "hex": "eebb05691fe79c77f6bcc234f166f67f1b73746f726167652e676f6f676c65617069732e636f6d",
    "base64": "7rsFaR_nnHf2vMI08Wb2fxtzdG9yYWdlLmdvb2dsZWFwaXMuY29t"
  },
  "bob": {
    "hex": "ee9448bcbe7ec853c6d378e8995ea5408673746f726167652e676f6f676c65617069732e636f6d",
    "base64": "7pRIvL5-yFPG03jomV6lQIZzdG9yYWdlLmdvb2dsZWFwaXMuY29t"
  }
}
```

Build bob's link by taking the printed `tg_url` and substituting his base64
secret for alice's:

```
tg://proxy?port=443&secret=7pRIvL5-yFPG03jomV6lQIZzdG9yYWdlLmdvb2dsZWFwaXMuY29t&server=203.0.113.9
```

Per-user links are printed in full — one per user, per accepted secret form —
under a `listeners` array once you add a `[[listener]]` block. That is
[[Connection-Types]].

You do not have to edit the file at all: `POST /secrets` adds or updates a user
on a running proxy. Those changes live in memory only and are overwritten by the
next `/reload` or restart, so the file stays the source of truth. See
[[Multi-User-and-API]].

## What next 🧭

- [[Configuration]] — every option, and which ones actually matter.
- [[Connection-Types]] — FakeTLS, obfuscated2 and WEB, and why a `[[listener]]`
  on a public address is fingerprintable as an MTProto proxy.
- [[Multi-User-and-API]] — the management API, bearer tokens, and running this
  behind a panel.
- [[Limits-and-Quotas]] — data caps, expiry dates and disabling a user.
- [[Monitoring]] — the full `/stats` response, Prometheus and statsd. Also where
  `track-client-ips` lives: it is off by default, deliberately, and reporting
  which addresses connect to a circumvention proxy is not a casual setting.
- [[Security]] — what this proxy hides, what it does not, and what an operator
  is holding.
- [[WEB-Proxy-Setup]] — the WebSocket transport, which needs a hostname you
  control, a real certificate and a plausible cover site.
- [[Troubleshooting]] — `doctor`, common errors, and what the log lines mean.
- [[FAQ]]
