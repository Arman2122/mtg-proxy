# Monitoring

mtg-proxy reports on itself in several places, and they overlap less than you
might expect:

- **The proxy's GET /stats** — live per-user counters as JSON, on the management API.
- **Per-user client addresses** — off by default, and usually should stay off.
- **Per-address usage** — what each address of one secret moved, on its own endpoint.
- **The WEB relay stats server** — new in v1.3.0, a loopback-only socket on the relay process.
- **Prometheus** and **statsd** — aggregate metrics from the event stream, with no per-user dimension.
- **Logs** — zerolog JSON on stdout.
- **What to alert on.**

The proxy and the WEB relay are two processes, and each reports only itself. The
proxy's `/stats` knows nothing about relay sessions, and the relay's `/stats`
knows nothing about the users behind them.

## The proxy's GET /stats 📊

The management API is off until you give it an address:

```toml
api-bind-to = "127.0.0.1:9090"
```

```bash
curl http://127.0.0.1:9090/stats
```

Bind it to loopback. If you must reach it from elsewhere, set `api-token` too —
it guards every route on this listener, `/stats` included, comparing the whole
`Authorization` header in constant time:

```toml
api-token = "a-long-random-string"
```

```bash
curl -H "Authorization: Bearer a-long-random-string" http://127.0.0.1:9090/stats
```

A full response, from a deployment that has an extra `[[listener]]`, a throttle,
and one user with limits:

```json
{
  "started_at": "2026-09-01T10:30:00Z",
  "uptime_seconds": 262800,
  "total_connections": 8,
  "features": [
    "client-ips",
    "faketls",
    "listeners",
    "quota-reset",
    "secret-modes",
    "secrets-api",
    "web-relay"
  ],
  "throttle": {
    "active": false,
    "limit": 5000
  },
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
      "last_seen": "2026-09-04T11:25:30Z",
      "quota_used": 3145728,
      "quota": 10737418240,
      "quota_remaining": 10734272512,
      "quota_reset": "monthly",
      "expires_at": "2026-12-31T00:00:00Z"
    },
    "bob": {
      "connections": 0,
      "bytes_in": 0,
      "bytes_out": 0,
      "last_seen": null,
      "quota_used": 0
    }
  }
}
```

### Top-level fields

| Field | Meaning |
|---|---|
| `started_at` | When this process came up. |
| `uptime_seconds` | Seconds since `started_at`. Smaller than you expect means the process restarted. |
| `total_connections` | The sum of the live per-user `connections` gauges right now. It is not a lifetime count. |
| `features` | Sorted capability names this build supports. |
| `throttle` | Present only when `[throttle] max-connections` is set. |
| `listeners` | Present only when at least one `[[listener]]` is configured. |
| `obfuscated` | Same condition as `listeners`. |
| `faketls_handshake` | Present once the FakeTLS door has counted something: one `ee` hello that got past the hostname check. A proxy nobody has connected to yet does not show it. See below. |
| `users` | Always present, keyed by secret name. |

`features` is a public contract, not a version string. A panel reads it to find
out whether the binary understands a setting before offering it. Names are never
renamed or removed, only appended, and the seven above are the v1.3.0 list. Note
that `client-ips` says the binary understands `track-client-ips`, not that this
deployment has it on — only the presence of the address fields says that.

`listeners` reports what each socket accepts. Every `bind-to` address is listed
first with `accept: ["ee"]` and `public: true`: that port serves FakeTLS and
nothing else, and there is deliberately no way to make it accept `dd` or
`plain`. A `[[listener]]` stanza reports its own accept set, and its `public`
flag is your written acknowledgement that a non-loopback obfuscated2 socket is
fingerprintable as an MTProto proxy. See [[Connection-Types]].

### The obfuscated counters

These describe the pre-FakeTLS entry on your `[[listener]]` sockets, so they
appear only once you have one.

| Field | Meaning |
|---|---|
| `trials` | Connections that entered the trial-decryption loop. |
| `misses` | Connections no configured secret decrypted. |
| `denied` | Connections disposed of by the deny path, for any reason. |
| `rate_limited` | Connections turned away by the per-IP failed-handshake budget before reaching the loop. One of these is also counted in `denied`, and never in `trials`. |
| `draining` | A live gauge of refused connections sitting in a bounded drain right now. Every other number here is a total since start. |

`denied` deliberately does not break down by reason. A wrong secret, an
unhonoured transport, a replayed frame, a rate-limited peer and a
disabled/expired/over-quota user all take the same exit, because none of them
may be distinguishable to the peer either. A counter that separated them would
describe the oracle that exit exists to avoid building.

### The FakeTLS handshake counters

`faketls_handshake` describes what the FakeTLS door decided about each `ee` hello
that got past the hostname check, and the budget that bounds the CPU spent
answering them (see [[Configuration]], `[defense.handshake-budget]`). It is a
top-level object beside `users`, never inside it: nothing about the door is a
client, and a panel that bills every key under `users` must not see one. It is
omitted until the door has counted something, and every count is a total since
the process started.

| Field | Meaning |
|---|---|
| `hinted` | Hellos matched by one of the secrets the client's address had matched before: usually one HMAC, at most 16, outside the budget. Only with `hints` on. |
| `scanned` | Hellos matched by the scan over the hosted secrets. |
| `unmatched` | Hellos the scan found no secret for. They were fronted to the cover site. |
| `denied_ip` | Hellos refused because the client address's own bucket could not pay for a scan. Checked before the process-wide bucket. |
| `denied_global` | Hellos refused because the process-wide bucket could not pay. |
| `oversized` | Hellos above the scan cap of 128 SHA-256 blocks (about 8 KiB). Under `enforce` they are never scanned; `observe` counts them and scans them anyway. Always `0` under `off`, which has no cap. |
| `over_budget_matched` | `observe` mode only: hellos the budget would have refused that then matched a real secret. Always `0` under `enforce`. |
| `enforced` | Whether the budget acts on a refusal. `true` in `enforce` mode, `false` in `observe` and `off`. |
| `ns_per_block` | What the budget believes one SHA-256 block costs on this machine, in nanoseconds: the reading taken once at start, which every cost in the budget is divided by. About 30 on a CPU with SHA extensions, several hundred on one without. |

In `enforce` mode every hello that gets past the hostname check increments
exactly one of the first six. A replay, or a disabled or over-quota user, after a
match counts as its match: the counter says how the secret was found, not what
happened to the connection after. A hello that cannot be read, or whose hostname
matches no secret, is not counted here at all, and neither is one still waiting
for budget when the proxy shuts down: nothing was decided about it. In `observe` mode `denied_ip`,
`denied_global` and `oversized` count what `enforce` would have refused, and
each moves together with the `scanned` or `unmatched` of the scan that went ahead
anyway, so the first six no longer add up to the hellos. Under `off` the three
`denied`/`oversized` counters stay at zero.

With hints on, a deployment's returning clients show up as `hinted` and only
strangers (and clients whose address changed) as `scanned`. With hints off, every
match is `scanned`.

Besides the counters, each refusal is logged at info level with its reason
(`denied_ip`, `denied_global` or `oversized`), which the default warn level does
not show; `debug = true` does.

#### Running `observe` as a canary

Turning the budget on in front of real users is the one step that can front a
legitimate client, so watch first:

1. Set `mode = "observe"` under `[defense.handshake-budget]` and restart (the
   table is read at start). Nothing is refused and nothing waits: every hello is
   scanned as before, while the budget keeps its books exactly as `enforce` would.
2. Let real traffic run for a while, floods included if you get them, and read
   `faketls_handshake` from `/stats`.
3. `denied_ip`, `denied_global` and `oversized` are what `enforce` would have
   fronted. They include every probing hello that would have matched nothing, so
   they can be large during a flood, and that is expected.
4. `over_budget_matched` is the number that decides it: hellos the budget would
   have refused that nevertheless matched a real secret, which is the legitimate
   traffic `enforce` would have fronted. **If it stays at or near zero while
   real clients are connecting, enforcing would not have refused them.** Remove
   the key (or set `"enforce"`) and restart.
5. If it climbs, enforcing would have fronted real users. Raise `cpu-percent`
   (the process-wide bucket), raise `per-ip-ms` or set it to `0` if many clients
   share an address, or turn `hints` on so returning clients skip the scan, then
   watch again.

`over_budget_matched` exists only in `observe`: under `enforce` a refused hello is
never scanned, so nothing can say whether it would have matched. Under `enforce`
the signals are `denied_ip` and `denied_global` rising, and users reporting that
a client had to retry.

### Per-user fields

Always present for every user:

| Field | Meaning |
|---|---|
| `connections` | Live connections right now. |
| `bytes_in` / `bytes_out` | Lifetime traffic since this process started. |
| `last_seen` | Last connection time, or `null` for a user who has never connected. |
| `quota_used` | Bytes counted against the current quota period. Survives a restart only when `usage-state-file` is set. |

Present only when they apply, so an untouched deployment's response keeps the
shape it always had:

| Field | Appears when |
|---|---|
| `quota` | The user has a `[secret-limits.<name>] quota`. |
| `quota_remaining` | Same, clamped at zero rather than going negative. |
| `quota_cutoffs` | It is non-zero: streams this user had ended by reaching the quota. A quota nobody reaches shows none; a user whose cutoffs keep climbing is at their ceiling and retrying. |
| `quota_reset` | The user has a reset policy. `"monthly"` is the only value emitted. |
| `expires_at` | The user has an `expires` deadline. |
| `disabled` | The user is disabled. Omitted, not `false`, when enabled. |
| `speed_limit` | The user has a speed limit; this is it, in bytes per second. |
| `throttled_ms` | It is non-zero: milliseconds this user's connections have spent held to their speed limits, all connections summed, including the time held to the per-address limits (`client-speed`, `client-fair`) of the addresses they came from. A user with a limit and no `throttled_ms` is not reaching it; one whose `throttled_ms` grows a second every second is living at it. That is the honest measure of a cap — one nobody ever waits for is doing nothing. It never goes back, even when the per-address table forgets an address. |
| `ad_tag_skipped` | It is non-zero: an ad-tagged stream of this user's took the direct path because its transport has no middle-proxy reframer, losing its sponsored channel. A silent skip is a revenue bug nobody can diagnose, so it is reported. |
| `ad_tag_failed` | It is non-zero: an ad-tagged stream on a transport the middle proxy *does* handle took the direct path anyway, because the middle proxy could not be reached or refused it. Unlike a skip this is not by design — a server that cannot reach `core.telegram.org`, or a revoked tag, shows up here and nowhere else. A few right after a restart are normal: clients reconnecting in the first couple of seconds, before the middle-proxy config has loaded, go direct rather than wait. |
| `ip_limit` | The user has a `[secret-limits.<name>] ip-limit`: how many places they may be at once. |
| `active_ips` | It is non-zero: how many places the user counts as being in right now — the addresses of their live connections here plus any a panel reported from elsewhere. A count, so it is never gated. Above `ip_limit` means the limit was lowered under open connections, which are never dropped for it. |
| `ip_limit_refused` | It is non-zero: connections turned away for arriving from one place too many. A limit nobody ever hits is doing nothing; a user hitting it constantly is sharing a secret or roaming between networks, and `active_ips` tells the two apart. |
| `client_conns` | The secret has `client-conns`: how many live connections one address may hold to it. |
| `client_conns_refused` | It is non-zero: connections turned away for arriving from an address that already held `client_conns` of them. There is no event and no Prometheus or statsd counter for it; this is the only place it shows. |
| `client_speed_limit` | The secret has `client-speed`: the per-address ceiling, in bytes per second. |
| `client_fair` | The secret has `client-fair = true`: its speed limits are divided among its addresses. |
| `clients` | It is non-zero: how many addresses the per-address table holds an entry for on this secret, live and idle (an entry is kept ten minutes after the address's last connection), the shared rest entry not counted. A count, never gated. |
| `clients_overflow` | It is non-zero: connections sent to the rest entry because the table had no room for their address, since the process started; a secret removed and added again starts from zero. Peers that do not stand for one place, which share the rest entry anyway, are not counted here. |
| `connected_ips` / `last_ip` | `track-client-ips` is on. See below. |
| `external_ips` / `external_expires_at` | `track-client-ips` is on and a panel has reported the user's addresses elsewhere through `PUT /secrets/{name}/external-ips`. See [[Multi-User-and-API]]. |

The throttle block reports `active` (whether caps are being applied at all),
`limit`, and `caps` — a per-user connection ceiling, present only while some
user is actually capped. Configuring it belongs to [[Limits-and-Quotas]].

`GET /secrets` on the same listener carries `connections`, `last_seen` and the
quota fields for each secret, so a panel rendering one user does not have to
fetch and filter the whole of `/stats`. See [[Multi-User-and-API]].

## Per-user client addresses 🔒

`track-client-ips` defaults to **false**, and that default is the point rather
than caution.

```toml
track-client-ips = false
```

With it on, each user gains two fields on `/stats` and on `GET /secrets`:

```json
"alice": {
  "connections": 2,
  "connected_ips": ["198.51.100.7", "203.0.113.44"],
  "last_ip": "203.0.113.44"
}
```

`connected_ips` is the distinct addresses holding a live connection right now,
sorted and deduplicated. It is derived from the connection registry rather than
counted separately, so it cannot drift from the `connections` gauge beside it,
and an entry disappears when its connection ends. `last_ip` is the address of
the most recent admitted connection, and it outlives that connection.

**Why it is off.** This is a circumvention proxy. The people using it are
frequently the reason it exists, and your answer to "who connected from where"
is also the answer available to whoever ends up holding the server — by seizure,
by compromise, or by a backup that went somewhere it should not have.
`connected_ips` adds no retention, because those addresses are already held for
the life of the connection and vanish with it. `last_ip` does add retention,
because it survives the connection it came from. A deployment that never asks
for either never accumulates one. (That is about these two fields. The ee
handshake budget keeps a separate anonymous per-address bucket in memory whatever
`track-client-ips` says; see *Client addresses* in [[Security]].)

With tracking on, the per-address table also keeps every address a secret is
used from, with what it moved, until ten minutes after its last connection, and
[`GET /secrets/{name}/clients`](#per-address-usage) lists it for up to about
eleven minutes: further back than `connected_ips`.

Neither field is written to disk in any form. `usage-state-file` persists quota
counters alone, so no address survives a restart.

Behind a front proxy, both report what the PROXY header carried — the client's
real address rather than the loopback peer. That is what makes them usable at
all in a WEB deployment, and it is also why the address you would be storing is
a real one. See [[Security]].

## Per-address usage

`GET /secrets/{name}/clients` (feature `client-stats`) is one secret's usage per
source address. The route and every field are on [[Multi-User-and-API]]; this
section is how to read it.

```bash
curl -s -H "Authorization: Bearer a-long-random-string" "http://127.0.0.1:9090/secrets/alice/clients?limit=20"
```

**Which addresses are there.** The per-address table holds an entry per address
for every secret when `track-client-ips` is on, and for a secret with a
per-address control (`client-conns`, `client-speed`, `client-fair`) whatever
tracking says. The addresses are listed only with tracking on. Without it the
answer is three things, `total`, `overflow` and `"tracking": false`, with no
`rest` and no rows, even when the table holds entries.

Then:

- **A row is not a live connection.** An entry is kept ten minutes after the
  address's last connection closes, and the sweep runs once a minute, so an
  address that left shows `"connections": 0` for up to about eleven minutes.
  `connected_ips` on `/stats` is live connections only.
- **IPv6 rows are /64s.** A row spells an IPv6 place as its /64
  (`2001:db8:1:2::/64`), the unit `ip-limit`, `client-conns`, kick and bans
  count, while `connected_ips` shows full addresses (`2001:db8:1:2::5`). Two
  devices in one /64 are one row. To kick a row, send its prefix address without
  the `/64`; ban and unban take either form.
- **`rest` is one row for many clients.** It stands for every peer that does not
  stand for one place — loopback, private, link-local, unspecified, multicast, or
  no address at all — and every address the table had no room for. Behind a
  carrier that forwards no client address, that is every client. It holds one
  fair share and has no ceiling. It is absent when the secret has no rest entry.
- **Connections come from the address ledger**, the live count `ip-limit`
  reads, while `rest.connections` counts the streams the rest entry governs. An
  address that overflowed into the rest entry and later got an entry of its own
  can be counted in both.
- **An absent rate means none.** `speed_limit` is the tighter of the address's
  `client-speed` and its fair share of `speed`; `speed_limit_up` and
  `speed_limit_down` are its fair shares of `speed-up` and `speed-down`.
- **A row's `throttled_ms`** is the time its streams waited at its own
  per-address limits. The user's `throttled_ms` on `/stats` includes it, plus the
  time held at the secret's own buckets.
- **Counters start again from zero** when an entry is dropped and made again: an
  address that comes back after more than ten minutes, and every address after a
  restart.
- **Times are UTC**, in whole seconds. `/stats` times are in the server's zone.
- **Order.** Rows are sorted by `bytes_in` plus `bytes_out`, most first, ties by
  address, and then cut to `limit` (100 by default, at most 1,000). `total`
  counts every entry, not the page.

**Watching fair share work.** With `client-fair` on, every row with a live
connection shows the same fair rate, the level of the last tick, whether the
address is busy or quiet: in `speed_limit` for a `speed` total (or the row's
own ceiling there, when that is lower), and in `speed_limit_up` or
`speed_limit_down` for a `speed-up` or `speed-down` total, with no ceiling
folded in. A row with `"connections": 0` keeps the rate it left at until it
comes back. A quiet address moves less than the level and keeps what it asks
for; the busy ones share the rest. If two busy addresses move very different
amounts for long, read *Fair share: what to expect* on [[Configuration]]: with
thousands of addresses the share can take about a minute to settle, and a
client that waits less than a quarter of the time is not corrected at all.

## The WEB relay stats server 🌐

New in v1.3.0. Before it the relay — the internet-facing half, the one
terminating sessions and carrying every byte — reported nothing at all, and an
operator's first sign of trouble was a user saying so.

It is off unless you give it an address:

```toml
[web]
stats-bind-to = "127.0.0.1:8100"
```

```bash
curl http://127.0.0.1:8100/stats
```

### It must be loopback, and it must be a second socket

The relay refuses to start if `stats-bind-to` is anything but a loopback IP
literal. `0.0.0.0:8100` is rejected. So is `localhost:8100`: a name could
resolve anywhere and could resolve somewhere else tomorrow, and there is no
reading of it the validator can safely accept without a lookup whose answer it
cannot pin. Use `127.0.0.1` or `[::1]`.

This is refused at startup rather than warned about, because the socket answers
with no credential at all. How many sessions are live and how many bytes have
moved is exactly the traffic analysis this transport exists to deny. An operator
who typed a public address has published that, and a line in a log is not where
they would find out.

It is deliberately a separate listener, not a path on `[web] bind-to`. That
socket is published to the internet by your front proxy, and it holds one
invariant: anything not carrying a credential this relay minted is answered by
the cover site, on every path. A real endpoint there breaks it. A 401, a JSON
body, even a distinctive response time is a signal that the hostname is not the
website it is pretending to be — and token-gating does not help, because the
gate itself is the fingerprint. So the counters live on a socket the front proxy
has never heard of.

Failing to bind here is fatal, unlike a failed extra `[[listener]]` on the
proxy. The reasoning is the opposite: there, losing one socket must not take the
public port down, because clients are on it. Here you asked for observability
and would otherwise get a relay that runs while silently reporting nothing.

The relay logs a startup line naming the address (`"stats":"(off)"` when unset),
but that line is at info level and the default log level is warn, so you will
not see it unless `debug = true`. Curl the socket instead — it is the same
question and a faster answer.

The server answers `GET /stats` and nothing else: any other path is a 404, any
other method a 405 with `Allow: GET`. Responses carry `Cache-Control: no-store`.

### The response

```json
{
  "started_at": "2026-09-01T10:30:00Z",
  "uptime_seconds": 262800,
  "profiles": ["alice", "bob"],
  "reloads": 2,
  "reload_failures": 0,
  "last_reload": "2026-09-03T22:14:05Z",
  "sessions": {
    "active": 37,
    "created": 4120,
    "attached": 4098,
    "max": 1024
  },
  "streams": {
    "active": 51,
    "opened": 20544
  },
  "bytes": {
    "up": 918273645,
    "down": 8172635449
  },
  "refused": {
    "cover_served": 19233,
    "not_found": 61,
    "bad_token": 12,
    "session_limit": 0
  }
}
```

`started_at` and `uptime_seconds` echo the proxy's field names on purpose, so
you do not have to translate between two documents.

`profiles` is the secret names in the relay's profile order, filled in at
startup and refreshed on reload. It is never `null`. The relay's own matching is
by capability and index and works without names; they are here so this report
lines up with the proxy's `/stats`, which is keyed by name.

`reloads`, `reload_failures` and `last_reload` cover both ways a reload happens:
the relay noticing that the file changed, and a `SIGHUP`. `last_reload` is
`null` until the first one lands. A file change that left the profiles as they
were — a comment, a limit, the proxy's own settings — is not a reload and moves
nothing; a `SIGHUP` that changed nothing still counts, because the operator who
sent it is asking whether it landed. A file the relay refused counts once, not
again on every look. On Windows the relay registers no reload signal, because
nothing there ever delivers SIGHUP; the file watcher runs there as everywhere.

**Sessions.** `active` is taken from the session store — the thing that actually
enforces the limit — rather than from a counter, so comparing it with `max` is
meaningful. `max` is `[web] max-sessions`, which defaults to 1024. `created`
counts admissions and `attached` counts carriers that reached the WebSocket, so
`created - attached` is sessions minted and never used: clients that gave up
between the page and the socket. There is deliberately no session gauge held
alongside the counters, because a session can be admitted and never attach, and
can also be reaped by the store's own expiry — a hand-maintained gauge would
drift upward forever.

**Streams** are the logical connections carried inside those sessions. `active`
is a gauge, `opened` a total.

**Bytes** are relay payload as the relay sees it: up is client to Telegram, down
is Telegram to client. Frame headers and WebSocket framing are excluded, so
these compare with the proxy's `bytes_in`/`bytes_out` rather than with anything
you would measure on the wire.

### The refusal breakdown

This is the part worth reading at three in the morning, because one number
cannot tell these apart.

| Field | What it counts | What a climb means |
|---|---|---|
| `cover_served` | Requests where nothing in the path, query or headers was recognised, so the cover site answered. | On a public hostname a normal value is not zero — this is largely the internet knocking, crawlers included. What matters is a sudden climb alongside users reporting failures: that is the signature of a hostname or secret-set mismatch, typically after a reload changed one and not the other. |
| `not_found` | Every tier-two answer: something authentic appeared in the request but was not usable, so the relay answered a local 404 and forwarded nothing. This includes the `bad_token` cases below, so it is always at least as large as `bad_token`. | Small steady numbers are clients retrying stale state. A climb with `bad_token` flat suggests clients holding capabilities this relay no longer serves. |
| `bad_token` | Session or carrier requests carrying a bearer this relay did not mint or had already spent — including a second socket trying to join a session that already has a carrier. | Usually clients reconnecting after the relay restarted, since tokens do not survive it. A sustained climb on a stable process is worth looking at. |
| `session_limit` | Admissions refused because the process was at `max-sessions`. | Any non-zero value is capacity, not abuse. Raise `max-sessions` or run another relay. |

### The relay has no other telemetry

There is no Prometheus exporter and no statsd on the relay process; `[stats]`
below is read by the proxy only. This JSON socket is all there is, so putting
the relay on a dashboard means scraping this endpoint and translating it
yourself.

## Prometheus

The proxy can export aggregate metrics built from its internal event stream.
Off by default:

```toml
[stats.prometheus]
enabled = true
bind-to = "127.0.0.1:3129"
http-path = "/"
metric-prefix = "mtg"
```

The path defaults to `/`, not `/metrics`. That catches people out, so spell it
out in the scrape config:

```yaml
scrape_configs:
  - job_name: mtg-proxy
    metrics_path: /
    static_configs:
      - targets: ["127.0.0.1:3129"]
```

`metric-prefix` becomes the Prometheus namespace, so the default prefix `mtg`
produces `mtg_client_connections` and the rest.

| Metric | Type | Labels |
|---|---|---|
| `mtg_client_connections` | gauge | `ip_family` |
| `mtg_telegram_connections` | gauge | `telegram_ip`, `dc` |
| `mtg_domain_fronting_connections` | gauge | `ip_family` |
| `mtg_iplist_size` | gauge | `ip_list` |
| `mtg_telegram_traffic` | counter | `telegram_ip`, `dc`, `direction` |
| `mtg_domain_fronting_traffic` | counter | `direction` |
| `mtg_ip_blocklisted` | counter | `ip_list` |
| `mtg_domain_fronting` | counter | none |
| `mtg_concurrency_limited` | counter | none |
| `mtg_throttled` | counter | none |
| `mtg_ip_limited` | counter | none |
| `mtg_replay_attacks` | counter | none |

Label values: `ip_family` is `ipv4` or `ipv6`; `direction` is `to_client` or
`from_client`; `ip_list` is `allowlist` or `blocklist`.

Two limitations to be aware of before you build dashboards on this:

- **There is no per-user dimension.** These metrics come from the stream event
  pipeline, which does not carry the secret name into a label. Per-user
  connections, bytes and quota live on `GET /stats` and nowhere else. If you
  want per-user graphs, scrape the JSON.
- **Only the ten metrics above are registered.** No `go_*` or `process_*`
  collectors are added, so do not expect to alert on the proxy's Go heap or its
  file descriptors from this endpoint.

The scrape server carries its own deadlines (5s for headers, 10s for the
request, 30s to write, 120s idle), so a client that opens a connection and
dribbles bytes cannot pin a goroutine and a socket indefinitely.

## statsd

Also off by default, and it can run alongside Prometheus:

```toml
[stats.statsd]
enabled = true
address = "127.0.0.1:8125"
metric-prefix = "mtg."
tag-format = "datadog"
```

`address` is a UDP endpoint and has no default — set it. Delivery is
fire-and-forget: if the collector is down or a packet is dropped, nothing
anywhere says so, which is a good reason to keep `/stats` as the source of truth
for anything that matters.

The metric suffixes are the same as the Prometheus table above, but the prefix
is concatenated literally rather than joined as a namespace. `metric-prefix =
"mtg."`, with the trailing dot, is what produces `mtg.client_connections`; leave
the dot off and you get `mtgclient_connections`. `"mtg."` is the compiled-in
default, so the safest thing is to omit the key. Watch out for
`example.config.toml`, which sets it to `"mtg"` without the dot.

`tag-format` accepts `datadog`, `influxdb` and `graphite`, and anything else is
a startup error. The compiled-in default is `datadog`. Set it explicitly anyway
— the comment in `example.config.toml` claims the default is graphite, which
does not match the code, and an explicit value is immune to that being corrected
in either direction.

## Logs

Both the proxy and the relay write zerolog JSON to stdout, one object per line:

```json
{"level":"warn","timestamp":1788600000000,"logger":"proxy","message":"throttle activated"}
```

`timestamp` is unix milliseconds. The standing fields are `level`, `logger` (a
dotted component name, `web-relay` for the relay) and `message`; individual
lines bind extra fields of their own.

**The default level is warn.** Setting `debug = true` in the config file drops
it to debug, which is genuinely verbose — per-stream lines — and is for
diagnosing a problem, not for running one. (`mtg-proxy simple-run` takes `-d`
for the same thing.) `example.config.toml` ships `debug = true`; a hand-written
config that omits the key gets `false`.

In debug mode the proxy logs its whole configuration once at startup with
`secret`, the named secrets' values and `api-token` replaced by a redacted
placeholder. Secret names are kept, because knowing which clients are configured
is the entire value of that line. A debug log is still a more sensitive artifact
than a warn-level one, and whatever ships your logs will read it.

Lines worth knowing, all at warn level unless noted:

- `throttle activated` — warn, so it is visible at the default level. Its
  counterpart `throttle deactivated` is info, so by default you see the throttle
  engage and never see it release. Watch `throttle.active` on `/stats` if you
  need both edges.
- `cannot start extra listener on <addr>` — one `[[listener]]` failed to bind.
- `cannot accept a new connection, retrying` with `retry_in` — a transient
  accept error: the descriptor table is full, or a peer reset between the
  kernel's accept and the proxy's. The loop pauses and tries again, doubling
  from 5ms to a second, and resets on the next accepted connection. A steady
  stream of these means the process is at its file-descriptor limit; check
  `LimitNOFILE` on the unit.
- `extra listener stopped; the public port keeps serving` — a `[[listener]]`'s
  socket broke for good. The public port is unaffected. The relay's backend is
  usually the one, and WEB clients get the cover site until a restart.
- `public listener <addr> stopped: ...` — the public socket broke for good,
  and the process **exited** with that error rather than run on looking
  healthy while serving nobody. Under `Restart=on-failure` it is back a few
  seconds later; see [[Troubleshooting]].
  The proxy keeps running on the rest, deliberately: one bad stanza must not
  take the public port down.
- `SNI-DNS mismatch: ...` — the secret's fronting hostname does not resolve to
  this server's public IP. See [[Troubleshooting]].
- `ee handshake budget calibrated` with `ns_per_block` — info, so debug only. The
  reading the scan budget divides every cost by, taken once when the first proxy
  in the process starts; `/stats` carries the same number.
- `ee hello refused by the scan budget` with `reason` — info, so debug only, and
  one per refused hello, so verbose under a flood. `reason` is `denied_ip`,
  `denied_global` or `oversized`. The `/stats` counters of the same names are the
  way to watch it at the default level. The line carries the stream's `stream-id`
  and `client-ip` like every stream line (the `Stream has been started` line
  already logs the address of every connection at that level). The per-address
  bucket is never logged; the stream logger is separate from it.
- `per-address controls are in use and this listener expects PROXY headers: ...`
  — warn, once per such listener at start, with fields `listener` and `keys`.
  Some secret has `client-conns`, `client-speed` or `client-fair`, and the
  address those act on is whatever the PROXY header claims. See *Per-address
  controls* on [[Configuration]]. A reload that adds the keys later does not log
  it.
- `connection denied by per-user limit` with `deny_reason` `client_conns` or
  `banned` — info, so debug only, like the other reasons. It carries the stream's
  `client-ip` like every stream line. `client_conns_refused` on `/stats` is the
  way to watch the first at the default level; a ban refusal has no counter.
- `addresses banned through the API` and `ban lifted through the API` — info,
  with the secret's name and, for a ban, how many places were banned and how many
  streams closed. No address.
- `web relay reload: ...` — one line per refused reload, each saying which
  profiles were kept, with `trigger=file` or `trigger=signal` for where it came
  from.
- `web relay stats server stopped` — the counters socket died while the relay
  carried on.

## What to alert on 🚨

None of this is configured for you. These are the numbers that have turned out
to mean something.

On the proxy, from `GET /stats`:

- `uptime_seconds` going backwards between two scrapes. A crash loop looks
  exactly like a healthy proxy in every other field.
- `obfuscated.denied` and `obfuscated.rate_limited` climbing together on a
  `public = true` listener. That port is fingerprintable by design, and this is
  what being found looks like. `misses` climbing alongside `trials` says the
  same thing more quietly.
- `obfuscated.draining` sitting high. It is a gauge of connections being drained
  right now, so a persistently large value means the drain is where your
  connections are going.
- `faketls_handshake.denied_global` climbing. The process-wide scan budget is
  spent: someone is making the proxy try hellos that match nothing (compare
  `unmatched` and `oversized`), or the proxy hosts so many secrets that real
  clients cannot be paid for (check `ns_per_block` against `cpu-percent`). Under
  `enforce`, clients with no hint are being fronted and retrying. `denied_ip`
  climbing alone points at one place, or many users behind one address, spending
  its own bucket.
- `faketls_handshake.over_budget_matched` above zero while running
  `mode = "observe"`. Those are real clients `enforce` would have fronted; see
  the canary steps above before you switch.
- `throttle.active` true for more than a moment, or a user appearing in
  `throttle.caps` and staying there. See [[Limits-and-Quotas]].
- Per user, `quota_remaining` approaching zero or `expires_at` approaching. Both
  are silent when they land: the user is routed to the fronting domain and sees
  what a wrong secret sees.
- Per user, `client_conns_refused` climbing. Some address is holding
  `client_conns` connections and asking for more. One heavy device is the case the
  cap is for; a carrier's NAT with many people behind one address, or a front
  that sends no PROXY header, looks the same, so check `/clients` before you
  lower anything.
- Per user, `clients_overflow` above zero. The per-address table had no room —
  4,096 entries for the secret, counting the ones idle for up to ten minutes, or
  32,768 in all — and new addresses are sharing the rest entry, which has no
  ceiling. `clients` near 4,096 on a secret with a modest `ip-limit` points at
  many addresses passing through, such as one IPv6 holder rotating /64s.
- Per user, `throttled_ms` growing about a second a second on a secret with
  `client-speed` or `client-fair`. Someone is living at a per-address limit;
  `/clients` says which address, by its own `throttled_ms`.
- At start, the `per-address controls are in use and this listener expects
  PROXY headers` warning on a listener that anyone but your own front can reach.

On the WEB relay, from its own `/stats`:

- `refused.session_limit` above zero at all, and `sessions.active` approaching
  `sessions.max`.
- `refused.cover_served` climbing sharply at the same time as user reports. On
  its own it is background noise.
- `reload_failures` incrementing. That is a reload that was refused — a file the
  relay would not take, or a `[web]` change that needs a restart — whether the
  relay found the change itself or a SIGHUP asked for it. It is the only way to
  tell a refused SIGHUP apart from one that never arrived, where no counter
  moves at all.
- `sessions.created - sessions.attached` growing faster than usual: clients are
  giving up between the page and the WebSocket, which usually means the front
  proxy is mishandling the upgrade. See [[WEB-Proxy-Setup]].

From Prometheus, if you run it:

- `mtg_replay_attacks` and `mtg_concurrency_limited` are counters that should
  normally stay flat.
- `mtg_throttled` and `mtg_ip_limited` (v1.7.0) count connections refused by
  the per-user connection throttle and by a user's address limit. Neither
  carries a user label — cardinality — so use `/stats` to find who: the
  `throttle` block for the first, `ip_limit_refused` for the second.
- `mtg_telegram_connections` at zero while `mtg_client_connections` is not:
  clients are arriving and Telegram is not reachable. Check
  `mtg_domain_fronting_connections` before you page anyone — a wrong secret
  starts a client connection and then goes to the fronting site, so on a
  probe-heavy public port that is what a scan looks like, not an outage.
