# mtg-proxy

mtg-proxy is a [Telegram MTProto proxy](https://core.telegram.org/mtproto) built to
serve many users from one process. Every user gets their own named secret, their own
fronting host, their own traffic counters and their own limits — and all of that can
change on a running proxy without dropping a connection. That is what makes it usable
as the engine behind a panel, and it is equally happy running on its own from a TOML
file.

It is a fork of [9seconds/mtg](https://github.com/9seconds/mtg). Everything that makes
the thing hard to block in the first place — FakeTLS, domain fronting, the doppelganger
traffic mimic, anti-replay, SOCKS5 chaining, IP blocklists and allowlists, Prometheus
and statsd metrics — is upstream's and behaves as upstream documents it. This fork adds
the multi-user layer on top: named secrets, a management API, per-user governance, the
sponsored channel that mtg v2 dropped, and the WEB transport.

Current release: **v1.7.0**. Building from source needs Go 1.26 or newer.

## How a client reaches it 🚪

Three doors, one set of users. A secret is sixteen key bytes, and the same key is valid
in every wire form; the prefix only tells the *client* which door to knock on. So one
person keeps one name, one quota bucket and one set of counters whichever they use.

- **FakeTLS** on `bind-to`, normally `:443`, secret spelled `ee…`. The default, and every
  client speaks it. That socket serves FakeTLS only — nothing else is sniffed on it.
- **obfuscated2** on a `[[listener]]`, secret spelled `dd…` or bare hex. Its `accept` list
  is a non-empty subset of `["dd", "plain"]`. On a non-loopback address this port is
  fingerprintable as an MTProto proxy, which is exactly what `public = true` is: your
  acknowledgement, not a switch that improves anything.
- **WEB** on a hostname you own, over a genuine certificate. The client loads a page and
  carries MTProto over a WebSocket, so a network in between sees a browser visiting a
  website.

[[Connection-Types]] compares the three and says which clients can use which.

## Features 📋

| Feature | What it does | More |
|---|---|---|
| Multiple secrets | One named secret per user, each able to front behind a different hostname. Upstream's single `secret = "…"` still works and becomes a user named `default`. | [[Multi-User-and-API]] |
| Per-user stats | `GET /stats` on `api-bind-to`: live connections, bytes in and out, last seen, quota use, and a sorted `features` list a panel reads instead of parsing version strings. | [[Monitoring]] |
| Management API | `GET`/`POST`/`PUT /secrets`, `GET`/`DELETE /secrets/{name}` and the `/adtag` routes add, remove and re-key users at runtime. `api-token` puts a bearer token on every endpoint. | [[Multi-User-and-API]] |
| Hot reload | `POST /reload` re-reads `[secrets]`, `ad-tag`, `[secret-ad-tags]` and `[secret-limits]` and swaps them in atomically; unaffected users stay connected. The WEB relay is a separate process that watches the same file and follows it by itself; `SIGHUP` makes that immediate. | [[Multi-User-and-API]] |
| Quotas, speed, addresses, expiry, disable | `[secret-limits.<name>]` gives a user a data cap (optionally resetting monthly), a speed limit shared by all of that user's connections on every door, an address limit — how many places they may be at once, which a panel can extend across its other systems — a deadline and an on/off switch. A disabled, expired or over-quota user is routed to the fronting domain, exactly like a wrong secret, so a prober cannot tell them apart. | [[Limits-and-Quotas]] |
| Connection throttling | `[throttle] max-connections` with a fair-share cap recomputed every few seconds: light users keep everything they have, and the rest of the budget is split among heavy ones. | [[Limits-and-Quotas]] |
| Sponsored channel | `ad-tag` routes matching clients through Telegram's middle proxies so your promoted channel sits at the top of their chat list. Needs a reachable public IP. | [[Configuration]] |
| WEB transport | `mtg-proxy web-relay` serves Telegram Desktop's WEB proxy type from the same config file. It uses the `dd` spelling of the user's existing key bytes, because a WEB-capable client refuses an `ee` secret before it opens a socket. | [[WEB-Proxy-Setup]] |
| Per-listener links | `mtg-proxy access` prints a ready-to-use link per user per accepted form for every `[[listener]]`, alongside the usual `tg://` links and, when `[web]` is enabled, a `web` object per secret. A loopback listener gets no link and says why. | [[Connection-Types]] |
| Client addresses | `track-client-ips` adds `connected_ips` and `last_ip` per user to `/stats` and `/secrets`. It defaults to false and should stay that way unless you have a concrete reason: this is a circumvention proxy, and who connected from where is dangerous data to hold. | [[Security]] |
| WEB relay counters | `[web] stats-bind-to` serves the relay's own sessions, streams, bytes and refusal reasons. Loopback only — the relay refuses to start on any other address, because that endpoint answers, with no credential, the traffic analysis this transport exists to deny. | [[Monitoring]] |
| Public IP and env vars | `public-ipv4` / `public-ipv6` for NAT'd or multi-homed hosts; `SECRET`, `SECRET_HOST`, `TAG` and `MTG_BIND_TO` for `telegrammessenger/proxy`-style container deployments. | [[Configuration]] |

## Choose your path 🧭

**A proxy running in five minutes.** Go to [[Quick-Start]]. Generate a secret for the
site you want to hide behind, write about five lines of TOML, and run it.

```bash
mtg-proxy generate-secret --hex storage.googleapis.com
```

**A deployment you will actually rely on.** Read [[Installation]] for the binary,
container and build-from-source routes and how to verify what you downloaded, then
[[Configuration]] for the options that matter. Read [[Security]] before you open the
port: the API can mutate secrets, so it belongs on loopback or behind `api-token`.

**The Telegram Desktop WEB transport.** Go to [[WEB-Proxy-Setup]]. It needs a hostname
you control, a browser-trusted certificate, a front proxy that terminates TLS, and a
plausible cover site on that hostname — nothing ships as a default cover site, because a
starter page many operators installed would be a better signature than anything the
protocol leaks. Be aware of how far this has been tested: end to end with Telegram
Desktop 7.1.2 on Windows through Caddy. Other client platforms and the `tg://webproxy`
link format have not been through the checklist, so treat what `mtg-proxy access` prints
as the reliable way to configure a client.

**Wiring a panel or a script to it.** Start at [[Multi-User-and-API]].

**Something is not working.** [[Troubleshooting]], and run `mtg-proxy doctor` first.

## The rest of the wiki 📚

- [[Installation]] — binaries, the `ghcr.io/arman2122/mtg-proxy` image, building from
  source, and verifying a download with checksums and the signed build attestation.
- [[Quick-Start]] — the shortest path from nothing to a working proxy and a link you can
  hand someone.
- [[Configuration]] — every TOML section, what each key does, and which ones need a
  restart rather than a reload.
- [[Connection-Types]] — FakeTLS, obfuscated2 and WEB side by side: what each looks like
  on the wire, which clients support it, and what `mtg-proxy access` prints for each.
- [[WEB-Proxy-Setup]] — the WEB relay end to end: signing key, `[web]` table, the backend
  `[[listener]]`, the front proxy, and carrying the client's address through every hop.
- [[Multi-User-and-API]] — named secrets, the management API, hot reload, and how a panel
  should drive them.
- [[Limits-and-Quotas]] — data quotas, monthly resets, expiry, disable, throttling, and
  persisting usage across restarts.
- [[Monitoring]] — the stats JSON, Prometheus and statsd, the WEB relay's own counters,
  and what to alert on.
- [[Security]] — threat model, what each default protects, why client-address tracking is
  off, and how to harden an exposed deployment.
- [[Troubleshooting]] — `mtg-proxy doctor`, common failure modes, and reading the logs.
- [[FAQ]] — short answers to the questions that come up most.

mtg-proxy is MIT-licensed. Issues and pull requests go to
[Arman2122/mtg-proxy](https://github.com/Arman2122/mtg-proxy).
