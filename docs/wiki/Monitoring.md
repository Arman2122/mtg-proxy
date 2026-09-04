# Monitoring

mtg-proxy reports on itself in several places, and they overlap less than you
might expect:

- **The proxy's GET /stats** — live per-user counters as JSON, on the management API.
- **Per-user client addresses** — off by default, and usually should stay off.
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
| `quota_reset` | The user has a reset policy. `"monthly"` is the only value emitted. |
| `expires_at` | The user has an `expires` deadline. |
| `disabled` | The user is disabled. Omitted, not `false`, when enabled. |
| `ad_tag_skipped` | It is non-zero: an ad-tagged stream of this user's took the direct path because its transport has no middle-proxy reframer, losing its sponsored channel. A silent skip is a revenue bug nobody can diagnose, so it is reported. |
| `connected_ips` / `last_ip` | `track-client-ips` is on. See below. |

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
for either never accumulates one.

Neither field is written to disk in any form. `usage-state-file` persists quota
counters alone, so no address survives a restart.

Behind a front proxy, both report what the PROXY header carried — the client's
real address rather than the loopback peer. That is what makes them usable at
all in a WEB deployment, and it is also why the address you would be storing is
a real one. See [[Security]].

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

`reloads`, `reload_failures` and `last_reload` cover `SIGHUP`. `last_reload` is
`null` until the first one lands. On Windows the relay registers no reload
signal at all, because nothing there ever delivers SIGHUP, so these three stay
at zero and a new profile set needs a restart.

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
  The proxy keeps running on the rest, deliberately: one bad stanza must not
  take the public port down.
- `SNI-DNS mismatch: ...` — the secret's fronting hostname does not resolve to
  this server's public IP. See [[Troubleshooting]].
- `web relay reload: ...` — one line per failure mode of a SIGHUP, each saying
  which profiles were kept.
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
- `throttle.active` true for more than a moment, or a user appearing in
  `throttle.caps` and staying there. See [[Limits-and-Quotas]].
- Per user, `quota_remaining` approaching zero or `expires_at` approaching. Both
  are silent when they land: the user is routed to the fronting domain and sees
  what a wrong secret sees.

On the WEB relay, from its own `/stats`:

- `refused.session_limit` above zero at all, and `sessions.active` approaching
  `sessions.max`.
- `refused.cover_served` climbing sharply at the same time as user reports. On
  its own it is background noise.
- `reload_failures` incrementing. That is a SIGHUP that arrived and was refused
  — a config the relay would not take, or a `[web]` change that needs a restart.
  It is the only way to tell that apart from a SIGHUP that never arrived, where
  no counter moves at all.
- `sessions.created - sessions.attached` growing faster than usual: clients are
  giving up between the page and the WebSocket, which usually means the front
  proxy is mishandling the upgrade. See [[WEB-Proxy-Setup]].

From Prometheus, if you run it:

- `mtg_replay_attacks` and `mtg_concurrency_limited` are counters that should
  normally stay flat.
- `mtg_telegram_connections` at zero while `mtg_client_connections` is not:
  clients are arriving and Telegram is not reachable. Check
  `mtg_domain_fronting_connections` before you page anyone — a wrong secret
  starts a client connection and then goes to the fronting site, so on a
  probe-heavy public port that is what a scan looks like, not an outage.
