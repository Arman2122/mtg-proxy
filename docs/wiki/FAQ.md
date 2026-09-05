# FAQ

Short answers to questions that come up repeatedly, each with a link to the page that carries the detail. If your question is "why is it doing this *right now*", start at [[Troubleshooting]] instead.

- Transports and secrets
- Networking
- Running it
- Security
- About the project

## Transports and secrets 🔑

### Do I have to re-issue secrets to use the `dd` form or the WEB transport?

No. A secret is sixteen key bytes. The `ee` prefix, the `dd` prefix and the bare 32-hex form are three spellings of the same key, and the prefix only tells the *client* which door to knock on. Nothing is per-listener, so an existing user keeps one name, one quota bucket and one set of counters whichever way they arrive.

`mtg-proxy access` prints each user's key already spelled the way each configured socket expects:

```bash
mtg-proxy access /etc/mtg-proxy/config.toml
```

New in v1.3.0: that output carries a `listeners` array with a ready-to-use link per user per accepted form, alongside the usual `ipv4`/`ipv6` FakeTLS links and the `web` object. A loopback listener gets no links and says why — that is what a WEB relay backend is supposed to look like. See [[Connection-Types]].

### Can one user connect over more than one transport at once?

Yes. The same key is valid on `bind-to` (FakeTLS), on an obfuscated2 `[[listener]]` and through the WEB relay simultaneously. All of those connections attribute to the same `[secrets]` name: one `connections` count, one `bytes_in`/`bytes_out` pair, one `quota_used`. Handing someone a `dd` link does not create a second account. See [[Multi-User-and-API]].

### Which clients support the WEB transport?

Telegram Desktop 7.1.2 or later, and nothing else today. 7.1.0 and 7.1.1 had a WebView2 bug that broke some WEB proxies on Windows, so 7.1.2 is the floor.

Be aware of how narrowly this has been exercised: Telegram Desktop 7.1.2 on Windows, end to end through Caddy. macOS (WKWebView) and Linux (WebKitGTK) are different engines running the same page and have not been through the acceptance checklist in `contrib/web-relay/README.md`. The `tg://webproxy` deep link is emitted for convenience, but its parameter names are copied from `tg://proxy` and are not confirmed against a real client — hand people the hostname and secret for the client's own two fields. See [[WEB-Proxy-Setup]].

### Why does my WEB client reject the secret I gave it?

Because it is the `ee` spelling. A WEB-capable client refuses an `ee` secret before it opens a socket, so there is no FakeTLS here at all — the TLS on that hostname is real. WEB uses the `dd` form of the same sixteen key bytes, which is what the `web` object from `mtg-proxy access` prints. Nothing is re-issued; only the spelling changes.

### Why does my non-loopback `dd` listener need `public = true`?

Because a socket that answers obfuscated2 is fingerprintable as an MTProto proxy. There is no TLS to hide inside and no cover site to fall back to — the listener cannot domain-front a probe, because relaying a TLS alert back out of a plaintext port would be worse than a reset. `public = true` is your acknowledgement of that, and it is required on any non-loopback `bind-to` in a `[[listener]]`. It also arms `handshakes-per-ip`, which is left off on loopback because every connection there presents `127.0.0.1` and one shared bucket is a self-DoS.

`bind-to` at the top level serves FakeTLS (`ee`) only, and always will. There is deliberately no key that makes it accept `dd` or `plain`; that needs a separate stanza and a separate socket. See [[Connection-Types]].

## Networking 🌐

### Does it support IPv6?

Yes, on both sides — they are separate settings.

Inbound, `bind-to` takes a literal IP (hostnames and `*` are rejected). `"[::]:443"` is dual-stack on Linux, macOS, FreeBSD and Windows, or you can list both families:

```toml
bind-to = ["0.0.0.0:443", "[::]:443"]
```

Outbound to Telegram, `prefer-ip` has four values:

| value | meaning |
|---|---|
| `prefer-ipv6` | both families, IPv6 first (the default) |
| `prefer-ipv4` | both families, IPv4 first |
| `only-ipv6` | IPv6 only |
| `only-ipv4` | IPv4 only |

Set `public-ipv6` if the address the outside world sees is not on a local interface — it is what `mtg-proxy access` builds links from, what `mtg-proxy doctor` checks the SNI-to-DNS match against, and, with an ad-tag set, what the middle-proxy handshake advertises. See [[Configuration]].

### Are keepalives and timeouts configurable?

Yes, in two tables. `[network.timeout]` takes `tcp`, `http`, `idle` and `handshake`; `[network.keep-alive]` takes `disabled`, `idle`, `interval` and `count`.

```toml
[network.timeout]
idle = "5m"
handshake = "10s"

[network.keep-alive]
disabled = false
idle = "15s"
interval = "15s"
count = 9
```

Those two timeout values are the built-in defaults; the keep-alive numbers fall back to the Go runtime's own behaviour when you leave them unset. None of this hot-reloads — only `[secrets]`, `ad-tag`, `[secret-ad-tags]` and `[secret-limits]` do, so a timeout change needs a restart. The WEB relay's own lifetimes (a two-minute bootstrap TTL, a two-minute reconnect grace) are compiled constants and are not configurable; nothing about them is negotiated with the client. See [[Configuration]].

### Does it work behind Cloudflare?

Nothing in this repository is tested behind a CDN, and no configuration for one ships. Treat it as unsupported and read the constraints before you try:

- FakeTLS on `bind-to` is not HTTP. The client completes that TLS handshake with the proxy itself, so anything that terminates TLS in front of it breaks that path outright.
- The WEB relay *is* genuine HTTPS with a WebSocket, so a reverse proxy in front is the intended shape — but the relay learns the browser's address only from a PROXY v2 header, or from the right-most `X-Forwarded-For` entry when the peer is loopback. There is no fallback to the socket's own peer, on purpose: behind a front proxy that address is `127.0.0.1` for every user alive, and silently attributing everyone to the loopback stops the blocklist matching and the per-IP limits counting with nothing in a log to say so.
- Whoever terminates TLS for the WEB hostname sees the live session bearer, which travels inside `Sec-WebSocket-Protocol`. That is also why the tested Caddy vhost discards its access log.
- That hostname has to be a single gateway. A CDN error page, a cached object or a split vhost hands a prober a difference between two components' answers, which is exactly the distinguisher the design removes.

[[WEB-Proxy-Setup]] has the chain that has actually been run: HAProxy to Caddy to relay to proxy, with the client's address carried across all four hops.

## Running it 🔧

### How do I add a user without dropping anybody?

Two ways, neither of which restarts the proxy. Add the secret to `[secrets]` in the config file and ask for a reload:

```bash
curl -X POST http://127.0.0.1:9090/reload
```

Or add it directly through the API:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"name":"carol","secret":"ee367a…"}' http://127.0.0.1:9090/secrets
```

Both go through the same atomic swap. The new secret works immediately; every other user keeps their connection and their counters. Only a secret that was removed or re-keyed has its connections closed. API mutations are in-memory only, so write the file too — a later reload or a restart re-reads it and overrides them.

If you also run the WEB relay, it is a second process and does not share that listener — but it watches the file, and applies a changed `[secrets]` table by itself within a few seconds of the write. Nothing has to be sent. To apply it immediately rather than on the next look:

```bash
systemctl reload mtg-proxy-web-relay
```

What the relay cannot see is a change made through the API and never written to the file. That user's WEB link is answered by the cover site — which, from their side, looks exactly like the censorship the relay exists to get around. Write the file. See [[Multi-User-and-API]].

### What happens to sessions when I restart the relay?

Every live WEB session ends. Session state is held in memory only, so a restart drops all of it; clients then run their own retry ladder, reload the bridge page and bootstrap a new session. Links do not change — the signing key lives on disk and the capability is derived from the hostname — so nothing has to be re-issued.

A reload — the automatic one when the file changes, or a `SIGHUP` — is the gentle path: it swaps the profile set and leaves live sessions alone. Anything else that changed under `[web]`, or the backend listener's `proxy-protocol` flag, is refused whole with "restart required" rather than half-applied, and an unreadable or invalid file keeps the running set. Windows builds have no `SIGHUP`; the file watcher is the only trigger there. Rotating `token-key` invalidates every live session by design. See [[WEB-Proxy-Setup]].

### Can I see the relay's own counters?

Yes, from v1.3.0, on a socket of its own:

```toml
[web]
stats-bind-to = "127.0.0.1:8100"
```

```bash
curl http://127.0.0.1:8100/stats
```

It reports sessions, streams, bytes, reloads and why requests were refused. Empty is the default, which means no stats server. The address must be loopback and the relay refuses to start otherwise: this endpoint answers, with no credential at all, how many sessions are live and how many bytes have moved — the exact traffic analysis this transport exists to deny. It is also deliberately not a path on the public origin, where anything without a credential the relay minted is answered by the cover site. See [[Monitoring]].

## Security 🛡️

### Does it support replay protection?

Yes. `[defense.anti-replay]` keeps a stable bloom filter of connection fingerprints, so a byte-flow repeated by a prober — immediately or hours later — does not get the same answer twice. On FakeTLS the fingerprint is the ClientHello session ID, and a repeat is routed to the fronting domain exactly like a wrong secret. On an obfuscated2 listener it is checked only *after* a secret matched (unauthenticated probes writing into a stable filter would evict the FakeTLS entries the public listener depends on), and a replayed frame takes the same exit as every other refusal, so it is not distinguishable from one.

One thing worth knowing: the default is off. `example.config.toml` ships with it on, but a minimal config that omits the block gets no cache at all. Turn it on explicitly:

```toml
[defense.anti-replay]
enabled = true
max-size = "1mib"
error-rate = 0.001
```

The filter is approximate by design — `max-size` and `error-rate` trade memory against false positives. See [[Security]].

### Is it safe to expose the management API?

No. Bind it to loopback:

```toml
api-bind-to = "127.0.0.1:9090"
```

The API can add, re-key and delete secrets and set the ad-tag, so reaching it is equivalent to owning the proxy's users. If it must be reachable from elsewhere, set `api-token` and every endpoint requires `Authorization: Bearer <token>`; missing or wrong tokens get a `401`.

A token is authentication, not encryption. The API server speaks plain HTTP — there is no TLS anywhere in it — so a token that crosses an untrusted network crosses it in the clear, along with every secret in the response. Put a TLS terminator, an SSH tunnel or a WireGuard link in front of it. See [[Security]] and [[Multi-User-and-API]].

### Can I see which IP each user connects from?

Only if you switch it on, and it is off by default on purpose:

```toml
track-client-ips = true
```

With it on, `/stats` and `/secrets` add `connected_ips` (the distinct addresses holding a live connection right now) and `last_ip` (the most recent admitted connection's address) per user. This is a circumvention proxy: the people using it are frequently the reason it exists, and your answer to "who connected from where" is also the answer available to whoever ends up with the server. `connected_ips` adds no retention — those addresses are already held for the life of the connection and vanish with it — but `last_ip` outlives the connection it came from, so a deployment that never asks for either never accumulates one. Neither is written to disk in any form; `usage-state-file` persists quota counters alone.

Behind a front proxy both report what the PROXY header carried, which is the client's real address. Think about it before enabling it, and see [[Monitoring]] and [[Security]].

## About the project 📦

### Is this a fork, and what did it change?

Yes, a fork of [9seconds/mtg](https://github.com/9seconds/mtg). Everything that makes it hard to block is upstream's and behaves as upstream documents it: FakeTLS, domain fronting, the anti-replay cache, the doppelganger traffic-shape mimicry, SOCKS5 chaining, IP blocklists and allowlists, Prometheus and statsd.

What this fork adds is the multi-user layer on top — named secrets with per-user fronting hosts, per-user stats, a secrets and ad-tag management API, hot reload without dropping users, the sponsored-channel ad-tag that upstream v2 dropped, fair-share connection throttling, per-user quotas with expiry and a disable switch, the obfuscated2 `[[listener]]` stanza, the WEB relay, a public-IP override and Docker-style environment variables. See [[Home]].

### What does the panel integration expect?

mtg-proxy runs as a managed child process of the Penhoon panel, one process per MTProto inbound, each serving many client secrets. Four things are frozen contracts, and `internal/config/panel_contract_test.go` pins the first of them from this side:

- **The rendered config shape.** `bind-to`, `api-bind-to`, `api-token`, `[throttle]`, a loopback `[[listener]]` carrying no `public` key, and `[secrets]` last. Section order is load-bearing: in TOML every key after a header belongs to that table, so anything written below `[secrets]` is parsed as a secret.
- **The management API.** `PUT /secrets` and `POST /secrets/{name}/reset-quota` in particular, with a bearer token. The panel writes `[secrets]`, `[secret-ad-tags]` and `[secret-limits]` to the file first and calls the API second, because API mutations are memory-only.
- **The `features` array on `/stats`.** `client-ips`, `faketls`, `listeners`, `quota-reset`, `secret-modes`, `secrets-api`, `web-relay`. These strings are public API — never renamed or removed, only appended — so a panel can tell an old binary from a new one without parsing version numbers.
- **Release asset names.** `mtg-proxy-<version>-linux-<arch>.tar.gz`, with an inner directory of the same name holding a binary named exactly `mtg-proxy`, plus `mtg-proxy-<version>-checksums.txt`.

The WEB relay is a separate process, and nothing in this repository starts it for you — a WEB deployment is wired up by hand or by whatever supervises the proxy. The relay watches the config file precisely so that whoever is the source of truth for the secret set has nothing to tell it: write the file and the relay follows. See [[Multi-User-and-API]] and [[Installation]].
