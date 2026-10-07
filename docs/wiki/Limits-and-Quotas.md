# Limits and Quotas

mtg-proxy has two independent governors and they answer different questions.

`[secret-limits]` is per user: how many bytes one named secret may move, how fast, from how many places, until when it works, and whether it works at all. `[throttle]` is server-wide: how connections are shared out when everybody arrives at once.

- [The two governors](#the-two-governors)
- [Per-user limits: `[secret-limits]`](#per-user-limits-secret-limits)
- [What a limited user actually sees](#what-a-limited-user-actually-sees)
- [How quota is counted](#how-quota-is-counted)
- [Persisting usage: `usage-state-file`](#persisting-usage-usage-state-file)
- [Resetting a quota](#resetting-a-quota)
- [Speed limits](#speed-limits)
- [Address limits](#address-limits)
- [Per-address controls](#per-address-controls)
- [Connection throttling: `[throttle]`](#connection-throttling-throttle)
- [Worked example: a small paid deployment](#worked-example-a-small-paid-deployment)
- [Limits that live elsewhere](#limits-that-live-elsewhere)

## The two governors

| | `[secret-limits]` | `[throttle]` |
|---|---|---|
| Scope | one named secret | every user on the proxy |
| Measures | relayed bytes, throughput, distinct addresses, a wall-clock deadline, an on/off flag | live connection count |
| Checked | on every new connection; the quota on every byte as well | on every new connection |
| Recomputed | every 5s the clock is consulted: an expiry that passed or a period that rolled over takes effect then | every `check-interval`, default 5s |
| Survives a restart | only with `usage-state-file` | nothing to survive |
| Live sessions | closed for `disabled`, `expires` and an exhausted quota; never for speed or `ip-limit` | never closed |
| Visible in | `GET /stats`, `GET /secrets`, the log | `GET /stats`, the log |

## Per-user limits: `[secret-limits]`

Every named secret in `[secrets]` may carry a `[secret-limits.<name>]` table. A secret without one is unlimited, never expires, and is enabled.

```toml
usage-state-file = "/var/lib/mtg-proxy/usage.json"

[secret-limits.alice]
quota = "10GB"
quota-reset = "monthly"
speed = "5mbit"
speed-up = "1mbit"
speed-down = "5mbit"
ip-limit = 2
expires = "2026-12-31"
disabled = false

[secret-limits.bob]
quota = "500MB"
```

| Key | Meaning | Omitted means |
|---|---|---|
| `quota` | max relayed bytes in the current period; a human size (`"10GB"`, `"500MiB"`, `"1073741824B"`). In the file the unit is required — a bare integer is accepted by the API only | unlimited |
| `quota-reset` | `"none"` (a lifetime allowance) or `"monthly"` | `"none"` |
| `speed` | sustained throughput cap for the user, all connections and doors together, upload and download combined; `"5mbit"`, `"500kbit"`, `"1MB/s"` — see [Speed limits](#speed-limits) | unlimited |
| `speed-up`, `speed-down` | the same cap on one direction alone, from the client's side: `speed-up` holds what the client sends, `speed-down` what it receives. Each is its own bucket, and both apply on top of `speed` when that is set too | unlimited |
| `ip-limit` | how many places the user may be at once, an integer; a place is an IPv4 address or an IPv6 /64 — see [Address limits](#address-limits) | unlimited |
| `expires` | RFC3339 (`"2026-12-31T00:00:00Z"`) or a plain date (`"2026-12-31"`) | never expires |
| `disabled` | `true` rejects the secret without removing it | `false` |

Four things about these values are easy to get wrong.

**Sizes are binary.** `quota = "10GB"` parses to 10 × 1024³ = 10737418240 bytes, and `"500MB"` to 500 × 1024². `GB` and `GiB` mean the same thing here. If you bill in decimal gigabytes, write the byte count out.

**A bare date is UTC midnight, and the deadline is exclusive.** `expires = "2026-12-31"` becomes `2026-12-31T00:00:00Z`, and the secret is refused from that instant on — the last day it works is the 30th. Write `"2026-12-31T23:59:59Z"` if you meant the end of the month.

**Table ordering matters.** In TOML every key after a `[table]` header belongs to that table, so `[secret-limits.*]` and `[secrets]` must come after all your global keys. Put `[secrets]` last of all. This is the single most common way to break a working config file — see [[Configuration]].

**A typo in a key is not an error, but it is named.** The TOML parser does not reject unknown fields (that is deliberate: it lets a config written for a newer mtg-proxy load on an older binary instead of taking the inbound offline). So `quota_reset = "monthly"` with an underscore parses fine and does nothing — and since v1.8.0 the proxy says so, with a warning naming `secret-limits.alice.quota_reset` at startup and on every reload, and `mtg-proxy doctor` lists it. A typo in the *secret name* is still refused outright: `[secret-limits.ghost]` with no `ghost` in `[secrets]` fails validation at startup with `secret-limits refers to unknown secret "ghost"`.

Changes to this file take effect on `POST /reload` or a restart. There is no SIGHUP reload for `mtg-proxy run` (SIGHUP is wired for `mtg-proxy web-relay` only, and the relay does not read this table at all — it watches the file for `[secrets]` alone).

```bash
curl -X POST http://127.0.0.1:9090/reload
```

## What a limited user actually sees

A disabled, expired or over-quota user is not told anything. On the FakeTLS listener the connection is routed to the fronting domain, exactly as a wrong secret would be, so a prober cannot tell a revoked customer from a wrong guess. On an obfuscated `[[listener]]` it takes the same exit as every other refusal on that socket — close or drain, per that listener's `on-unknown-secret` — so the deny reason is not readable by timing one connection against another. See [[Security]] for why every refusal on that door has to look alike.

The operator's view is the log. The proxy writes `connection denied by per-user limit` with `secret_name` and a `deny_reason` of `disabled`, `expired`, `quota_exceeded`, `ip_limit`, `client_conns` or `banned`. The line is at info level, which `debug = true` shows.

An address an operator has banned from the secret is turned away the same way as a disabled user: routed to the fronting domain on the FakeTLS listener, and the usual exit on an obfuscated one. A connection over the [per-address connection cap](#per-address-controls) is refused like an address-limit refusal, below.

A user at their [address limit](#address-limits) is the one refusal that is not routed to the cover site. It happens at admission, after the secret has matched, so only someone holding the valid secret can ever see it and there is nothing for a prober to learn; the connection is simply closed, on the FakeTLS door after the TLS answer and on an obfuscated listener through that socket's usual exit.

Disabling or expiring a secret also **closes that user's live connections**: at once when the change lands via reload or the API, and within five seconds when the clock crosses an expiry on its own. Reaching the quota ends the stream that reaches it, at that byte, and closes any other stream of that user on its next byte or at the next sweep. Since v1.8.0 none of this waits for the user to reconnect.

## How quota is counted

`quota_used` counts bytes read from and written to the **client** during the relay phase — the two directions summed. The handshake is not counted, and traffic sent to the fronting domain on a refused connection is not counted (it is not attributed to any user).

The check happens twice: at admission, and on every byte.

```
at admission:   if quota is set and quota_used >= quota:  refuse this connection
on every byte:  read or write only what is left; at the byte that reaches the quota, end the stream
```

**A quota is a ceiling, not a gate.** Alice has a 10 GB quota and has used 9.9 GB. She opens a connection — admitted, because 9.9 < 10 — and starts a 40 GiB download. She receives 100 MB and the stream ends there, at the byte that reached the cap; any other connection she has ends on its next byte, and an idle one within five seconds. Her `quota_used` reads exactly 10 GB. Her next connection is refused at the door. `quota_cutoffs` on `/stats` counts the streams the ceiling ended, which is how you tell a quota that is doing its job from one nobody reaches. (Before v1.8.0 the quota was checked only at admission and a live stream could overshoot it without limit.)

Two or more streams of one user moving bytes in the same instant can each deliver up to one read's worth past the cap, so the count can run a few kilobytes over. It cannot run a download over.

Monthly reset is by **calendar month**, not by a 30-day window from signup. The counter zeroes when the wall clock crosses into a new month, so a user added on the 20th gets a full allowance eleven days later. The rollover happens whenever the user next tries to connect, and every five seconds in the background, whether or not `usage-state-file` is set.

Both `/stats` and `/secrets` report usage, with one difference: `/stats` always includes `quota_used` for every user, while `/secrets` includes it only for users who have a quota configured.

```json
{
  "users": {
    "alice": {
      "connections": 2,
      "bytes_in": 1048576,
      "bytes_out": 2097152,
      "last_seen": "2026-09-04T11:25:30Z",
      "quota_used": 3145728,
      "quota": 10737418240,
      "quota_remaining": 10734272512,
      "quota_reset": "monthly",
      "expires_at": "2026-12-31T00:00:00Z"
    }
  }
}
```

`quota`, `quota_remaining`, `quota_reset`, `expires_at` and `disabled` appear only when that user has the corresponding limit set, and `quota_cutoffs` only once a stream has been ended by the cap. `quota_remaining` is clamped at zero.

## Persisting usage: `usage-state-file`

```toml
usage-state-file = "/var/lib/mtg-proxy/usage.json"
```

Without this key, quota accounting is in-memory only: every restart hands every user a fresh allowance. With it, the proxy loads the file at startup and rewrites it atomically (temp file, then rename) every ~30 seconds and once more on shutdown.

What is written is exactly two numbers per secret — the used-byte counter and the start of the current quota period:

```json
{"alice":{"quota_used":3145728,"period_start":1756944000000000000}}
```

Three consequences worth knowing.

**`bytes_in` and `bytes_out` are not persisted.** They are lifetime display counters and reset to zero on restart; `quota_used` is the one that survives. Do not bill from `bytes_in`/`bytes_out`.

**No client addresses are written, ever.** The file holds quota counters and nothing else, which is why enabling `track-client-ips` (off by default, and it should stay that way on most deployments — see [[Security]]) still leaves nothing on disk to seize.

**The file is keyed by secret name and entries are never pruned.** Delete a user and their counter stays in the file; add a *new* user under a recycled name and they inherit the old usage. If you reuse names, reset the quota after re-adding, or edit the stale entries out of the file while the proxy is stopped.

A bad path is not a startup failure. The proxy logs `cannot load usage state` once and `cannot flush usage state` every 30 seconds thereafter, and keeps proxying. Make sure the directory exists and is writable by the user the proxy runs as — nothing creates it for you.

## Resetting a quota

Zero one user's counter and restart their quota period from now:

```bash
curl -X POST http://127.0.0.1:9090/secrets/alice/reset-quota
```

With an `api-token` configured:

```bash
curl -X POST -H "Authorization: Bearer change-me" http://127.0.0.1:9090/secrets/alice/reset-quota
```

It answers `{"status":"ok"}`, or `404` for a name that is not in the active secret set. The reset is immediate in memory but only reaches `usage-state-file` on the next flush, so a process killed within ~30 seconds of a reset loses it.

To raise or remove a quota instead of clearing usage, edit `[secret-limits]` and reload. Limits changed through `POST /secrets` or `PUT /secrets` are **in-memory only** and are overwritten by the next reload — the config file is the source of truth. Note also that `POST /secrets` replaces the whole entry: omit `quota` from the body and that user's quota is cleared, not left alone. See [[Multi-User-and-API]] for the full route list.

## Speed limits

```toml
[secret-limits.alice]
speed = "5mbit"
```

A speed limit holds one user to a sustained throughput. It is the one limit here that shapes traffic rather than admitting or refusing it, and it is worth being precise about what it is.

**It is per user, not per connection.** Every connection alice has — every device, and every door: FakeTLS, obfuscated2, WEB — draws from one allowance. Two phones on one secret share `5mbit`; a second phone does not double it. This is the difference between a limit a panel can sell and one it cannot.

**It is enforced by the proxy, and can be nowhere else.** The proxy is the only hop that knows which user a byte belongs to: the secret is matched inside the handshake, while the operating system, a firewall or `tc` see TCP flows from addresses — and one user has many addresses, many users share one. Anything outside the process shapes addresses. A tunnel in front (GRE, a TCP relay with PROXY protocol) changes nothing here, because identity never came from the address.

**It is a sustained rate with a one-second burst.** The bucket holds one second of the rate, so MTProto's small, bursty messages stay snappy while a download is held to the line. With `speed`, upload and download share the one number.

**Each direction can have its own.** `speed-up` caps what the client sends and `speed-down` what it receives, each on a bucket of its own, so a plan can be "1 Mbit up, 5 Mbit down" the way links are sold. They are per user like `speed`, they follow the same spelling and the same floor, and when `speed` is set as well a byte is paid for under both — the tighter cap is the one that holds. A panel with separate up and down rates writes these two and leaves `speed` alone.

**It never buffers.** The bucket only delays: a read is held until what it read has been paid for, a write until what it is about to write has. Backpressure therefore lands in the client's own TCP window and the kernel does the rest. Throttling a user costs the proxy no memory, and a throttled user cannot make it hoard data.

**It is smooth at low rates.** Each read and write is cut to what the bucket can grant at once, so a `128kbit` user gets a steady trickle rather than a 32 KB block every two seconds. The floor is `64kbit`.

**It is live.** Change it in the file and reload, or through the API, and the connections already open slow down or speed up without being dropped. Remove it and they are freed at once — no reconnect needed.

**Spelling.** Bit units are decimal, as every link is sold: `5mbit` is 5,000,000 bits a second, `500kbit`, `1gbit`; `2mbps` means the same. Byte units are base 2, as the quota is: `1MB/s`, `512KB`. The `/s` is optional, a bare number is bytes per second, and an explicit zero is refused — omit the key for unlimited. The file and the API share one parser, so a spelling one accepts the other does.

**Watching it.** `speed_limit`, `speed_limit_up` and `speed_limit_down` on `/stats` and `/secrets` are the configured caps in bytes per second. `throttled_ms` on `/stats` is the time the user's connections have spent held to any of them. A user with a limit and no `throttled_ms` is not reaching it; a user whose `throttled_ms` grows by a second every second is living at it — and that, not a complaint, is how you know the cap is the thing they are experiencing. See [[Monitoring]].

## Address limits

```toml
[secret-limits.alice]
ip-limit = 2
```

An address limit is how many places a user may be at once. It is the limit a panel sells as "two devices", and it is worth being precise about what is counted, because the obvious reading — two IP addresses, two connections — is wrong in both directions.

**It counts places, not sockets.** A Telegram client keeps several connections open at once, one per datacenter and more for media, and they all come from the same address. Those are one place. An address counts once however many connections it holds, and it stops counting the instant the last of them ends.

**A place is an IPv4 address or an IPv6 /64.** Hosts rotate the low 64 bits of an IPv6 address (privacy extensions), so counting each address would charge one phone for a dozen devices; the /64 is the network the device is on. A v4-mapped v6 address is its v4 address.

**It is enforced at admission, after the secret matched.** A connection from a place the user already holds is admitted. One from a new place is admitted only while the user is below the limit, and refused otherwise: closed, after the TLS answer on the FakeTLS door and through the socket's usual exit on an obfuscated `[[listener]]`. It is not routed to the cover site, and it does not need to be — only someone holding the valid secret can ever see this refusal. The log line is `connection denied by per-user limit` with `deny_reason` `ip_limit` and, as always, no address.

**The check and the registration are one step.** Two new places arriving in the same instant cannot both read "one below the limit" and both get in; exactly one does. And a slot is released by the same code that releases the connection, so a slot cannot leak without the connection leaking too.

**Lowering it never drops anyone.** Like the quota and unlike a disable, a limit lowered on a running proxy binds the next admission and leaves the connections already open alone. `active_ips` shows the user over the new limit until enough of their places let go.

**A place can be ended by hand.** `POST /secrets/alice/kick` with `{"ips":["203.0.113.9"]}` closes every stream alice holds from that place and leaves her others running; an IPv6 address kicks its whole /64, the unit the limit counts. It is the tool for a panel that decides which device is one too many itself — the limit refuses the next connection from a new place, the kick ends the ones a place already holds. The route is on [[Multi-User-and-API]].

**A device that changes networks gets its slot back when its old connections end.** A phone that walks from Wi-Fi to mobile data leaves its old sockets open on the proxy until they end, and with a limit of one it is refused from the new address until then. Telegram's own servers close a session that stops pinging within a minute or two, which ends the relay and frees the slot; `[network.timeout] idle` (default 5 minutes) is the outer bound. Lower it if this is your users' common complaint, and set the limit to what people actually own rather than to one.

**It can span more than this proxy.** A panel that also runs the user's VPN and SSH can report the addresses the user holds there, and they count here alongside the user's live connections:

```bash
curl -X PUT -H "Authorization: Bearer $TOKEN" http://127.0.0.1:9090/secrets/alice/external-ips \
  -d '{"ips":["198.51.100.7","2001:db8::1"],"ttl":"90s"}'
```

Alice on her VPN from two places is then refused a third place through the proxy, and admitted from either of the two. The report is pushed, never pulled: no network call sits in the handshake, and each report expires after its `ttl` (default two minutes, at most an hour), so a panel that dies takes its claims with it and the limit degrades to what this proxy can see rather than refusing everyone. The panel refreshes the report as a heartbeat, well inside the ttl. To enforce in the other direction — refusing the VPN because the user is already on the proxy twice — the panel reads this proxy's `connected_ips` and `connected_ips_last_seen`, which need `track-client-ips`. The routes are on [[Multi-User-and-API]].

**Watching it.** `ip_limit` is the configured limit and `active_ips` how many places the user counts as being in right now, on both `/stats` and `/secrets`; `ip_limit_refused` on `/stats` counts the connections turned away. A limit nobody ever hits is doing nothing; a user hitting it constantly is either sharing a secret or roaming between networks, and the two look different in `active_ips`. The addresses themselves — `connected_ips`, `external_ips` — appear only with `track-client-ips`, for the reasons on [[Security]]; the counts always do. Prometheus and statsd get an `ip_limited` counter, and with it a `throttled` counter for the connection throttle below. Nothing about addresses is written to disk or to the log.

## Per-address controls

```toml
[secret-limits.shared]
speed = "50mbit"
ip-limit = 30
client-conns = 16
client-speed = "10mbit"
client-fair = true
```

Every limit above is per user. When one secret is shared by many people, one of
them can take the whole `speed`, and nothing says who. Three optional keys act
on each address inside the secret, where an address is an IPv4 address or an
IPv6 /64, the unit `ip-limit` counts:

- **`client-conns`** caps how many live connections one address may hold to the
  secret. The next one is refused after the handshake, as an `ip-limit` refusal
  is, and counted in `client_conns_refused`. Lowering it never drops anyone.
- **`client-speed`** is a ceiling on one address, both directions together, in
  the same spelling and with the same floor as `speed`. Each address has its own.
- **`client-fair`** divides the secret's `speed`, `speed-up` and `speed-down`
  among its addresses: an address that wants less than an even split keeps what
  it wants, and the others share the rest. It needs at least one of those three.

All three are off by default and live on reload. Two things limit what they can
do. One address may be many people, behind a mobile carrier's NAT. And
loopback and private addresses do not stand for one place: they share one entry
per secret that is never capped and has no ceiling, so behind a carrier that
forwards no client address the keys do nothing. The full reference — what an
address is, PROXY-protocol listeners, how fair share settles, what is kept — is
under *Per-address controls* on [[Configuration]]. Per-address usage and
temporary bans are on [[Multi-User-and-API]].

## Connection throttling: `[throttle]`

```toml
[throttle]
max-connections = 2000
check-interval = "5s"
```

`max-connections` is the total connection budget across all users. Omit the whole table to disable throttling; `max-connections = 0` is a parse error, not "off". The value goes through a 16-bit parser, so the accepted range is 1–65535 — if you need a higher ceiling than that, `concurrency` is the setting you want. `check-interval` defaults to 5 seconds.

A background goroutine recomputes per-user caps on every tick. Users below the equal share keep everything they have; whatever budget they leave behind is split among the heavy users, repeatedly, until nobody new drops below the line.

Worked example — `max-connections = 100`, with A=1, B=1, C=90, D=110 live connections:

| Round | Pool | Budget | Equal share | Outcome |
|---|---|---|---|---|
| 1 | A, B, C, D | 100 | 25 | A and B are under 25, so they keep their connections and leave the pool; budget drops to 98 |
| 2 | C, D | 98 | 49 | nobody is under 49, so the loop stops and both are capped |

The result is `{"C": 49, "D": 49}`. A and B are not in the map at all, and a user with no cap is never refused.

Three things follow from this, and all three matter more than the algorithm does:

- **Existing connections are never killed.** In the example above 202 connections stay up against a limit of 100. The cap only governs admission, so the limit is a shaping mechanism, not a ceiling. `concurrency` (default 4096) is the hard ceiling on simultaneous connections.
- **Caps are up to `check-interval` stale.** A user who drops from 90 connections to 2 stays capped at 49 until the next tick — harmless — and a burst that arrives between ticks is admitted against the old caps.
- **The unit is the named secret, not the device.** Three phones on Alice's secret are one user with three connections. If you want per-device caps, issue per-device secrets.

The throttle refusal happens after the secret is identified, which on the FakeTLS door is after the TLS handshake has already been answered. A throttled client therefore sees a connection that establishes and then drops, rather than a connection that fails — from the user's side it looks like a flaky proxy, and that is the honest description of what a full server is.

State is reported on `/stats`, and the block is present only when throttling is configured:

```json
{
  "throttle": {
    "active": true,
    "limit": 2000,
    "caps": { "heavy-user": 245 }
  }
}
```

`caps` lists only the users who are actually capped, and is omitted entirely when nobody is. The log carries `throttle loop started` at startup, then `throttle activated` (a warning) and `throttle deactivated` as the state flips.

One gap to know about: throttle refusals are **not** exported to statsd or Prometheus. Concurrency-limited, blocklisted and replay events are; throttled ones are only in the log and in the `/stats` object above. If you alert on capacity, alert on `throttle.active` from `/stats`. See [[Monitoring]].

## Worked example: a small paid deployment

Three customers on one VPS. Alice pays monthly, Bob bought a one-off 500 MB trial, Carol's subscription runs out at the end of the year.

```toml
bind-to = "0.0.0.0:443"
api-bind-to = "127.0.0.1:9090"
api-token = "a-long-random-string"
concurrency = 8192
usage-state-file = "/var/lib/mtg-proxy/usage.json"

[throttle]
max-connections = 2000
check-interval = "5s"

[secret-limits.alice]
quota = "200GB"
quota-reset = "monthly"

[secret-limits.bob]
quota = "500MB"

[secret-limits.carol]
quota = "50GB"
quota-reset = "monthly"
expires = "2027-01-01T00:00:00Z"

[secrets]
alice = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"
bob   = "ee0123456789abcdef0123456789abcd9573746f726167652e676f6f676c65617069732e636f6d"
carol = "eefedcba9876543210fedcba98765432a9573746f726167652e676f6f676c65617069732e636f6d"
```

Note the layout: global keys, then `[throttle]`, then the `[secret-limits.*]` tables, then `[secrets]` last. `api-bind-to` is loopback and carries a token because these routes can rewrite the secret set.

Create the state directory before the first run — it is not created for you:

```bash
install -d -m 0700 -o mtg-proxy -g mtg-proxy /var/lib/mtg-proxy
```

Start it:

```bash
mtg-proxy run /etc/mtg-proxy/config.toml
```

Hand out the links:

```bash
mtg-proxy access /etc/mtg-proxy/config.toml
```

Check where everyone stands:

```bash
curl -s -H "Authorization: Bearer a-long-random-string" http://127.0.0.1:9090/stats
```

Bob renews his trial — clear his used bytes:

```bash
curl -X POST -H "Authorization: Bearer a-long-random-string" http://127.0.0.1:9090/secrets/bob/reset-quota
```

Carol charges back. Set `disabled = true` under `[secret-limits.carol]`, then reload — her live connections close at once:

```bash
curl -X POST -H "Authorization: Bearer a-long-random-string" http://127.0.0.1:9090/reload
```

Alice upgrades mid-month. Raise `quota` in the file and reload; her `quota_used` is untouched, so the new ceiling applies to the allowance she has already spent. Reset her quota as well if the upgrade is meant to start her month over.

## Limits that live elsewhere

These are limits too, but they are not per-user governance and are documented on their own pages:

- `concurrency` — the hard ceiling on simultaneous connections for the whole process (default 4096). [[Configuration]]
- `handshakes-per-ip` — a failed-handshake budget per client IP on a `[[listener]]`, armed only when that listener is `public = true`. On a loopback listener it would be one shared bucket an attacker empties for everyone, so it stays off there. [[Connection-Types]]
- `max-sessions`, `max-streams`, `max-frame-payload`, `carrier-batch-bytes` — the WEB relay's own ceilings, in a separate process with separate state. Per-user quotas still apply to WEB traffic, because it enters the proxy through a `[[listener]]` under the same secret name. [[WEB-Proxy-Setup]]
- Rate limiting of the management API itself — there is none. Bind it to loopback and set `api-token`. [[Security]]

If a user reports that the proxy "sometimes connects and sometimes doesn't", check `deny_reason` in the log and the `throttle` block on `/stats` before anything else. [[Troubleshooting]]
