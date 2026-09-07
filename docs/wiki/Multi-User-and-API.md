# Multi-User and API

One mtg-proxy process serves many users. Each user is a named entry in the
`[secrets]` table, and that name is the identity everything else is keyed on:
per-user counters, quotas, ad-tag overrides and the links `mtg-proxy access`
prints.

A small HTTP server on `api-bind-to` reports what those users are doing and lets
you add, re-key and remove them while the proxy is running. This page covers the
users, the whole HTTP surface, and exactly what a reload does and does not
change.

- [Named secrets](#named-secrets)
- [Turning the API on](#turning-the-api-on)
- [GET /stats](#get-stats)
- [The features array](#the-features-array)
- [Client addresses](#client-addresses)
- [Managing secrets at runtime](#managing-secrets-at-runtime)
- [The ad-tag routes](#the-ad-tag-routes)
- [Errors and status codes](#errors-and-status-codes)
- [Hot reload](#hot-reload)
- [Reloading the WEB relay](#reloading-the-web-relay)

## Named secrets

Every key in `[secrets]` is a user. The value is that user's secret, and users
may front behind different hostnames.

```toml
bind-to = "0.0.0.0:443"
api-bind-to = "127.0.0.1:9090"
api-token = "a-long-random-string"

[throttle]
max-connections = 5000

[secret-limits.bob]
quota = "50GB"
quota-reset = "monthly"

# [secrets] goes last. In TOML every key after a [header] belongs to that
# table, so a top-level option written below this line is parsed as a secret.
[secrets]
alice = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"
bob   = "ee0123456789abcdef0123456789abcd9573746f726167652e676f6f676c65617069732e636f6d"
```

The same ordering rule applies to `[secret-ad-tags]` and `[secret-limits]`:
write every global key above them. Both are validated against `[secrets]` at
startup, so a typo in a name is a config error
(`secret-limits refers to unknown secret "bobb"`) rather than a limit that
silently applies to nobody.

The single-secret `secret = "..."` form from upstream still works. It becomes
one user named `default`, and `[secret-ad-tags]` and `[secret-limits]` may refer
to that name.

**One user, several doors.** A secret is sixteen key bytes. The `ee`, `dd` and
plain spellings are the same key told three ways, and the prefix only tells the
*client* which entry to use. A user who connects over FakeTLS on `bind-to`, over
an obfuscated2 `[[listener]]`, or over the WEB relay is the same row in
`[secrets]` with one quota bucket and one set of counters. Since v1.3.0
`mtg-proxy access` prints a link per user per accepted form on every listener,
so handing someone a `dd` link does not create a second account. See
[[Connection-Types]].

## Turning the API on

`api-bind-to` starts the management server. Leave it unset and no server runs.

```toml
api-bind-to = "127.0.0.1:9090"
```

The server can mutate secrets, so treat it as an administrative interface. There
are two ways to protect it, and you want at least one:

- bind it to loopback, which is what the example above does, or
- set `api-token`, which requires a bearer token on **every** route.

```toml
api-token = "a-long-random-string"
```

```bash
curl -H "Authorization: Bearer a-long-random-string" http://127.0.0.1:9090/secrets
```

The token check wraps the whole mux, so it also guards paths that do not exist —
an unauthenticated probe cannot enumerate routes by their 404s. The comparison
is constant-time. A missing or wrong token gets `401` with a
`WWW-Authenticate: Bearer` header. When `api-token` is unset the API is
unauthenticated, which is why the loopback bind matters.

If the API address cannot be bound the proxy logs a warning and keeps relaying;
losing the management port never takes the users offline. When `debug = true`,
the startup line records which mode you got:

```json
{"level":"info","auth":"bearer-token","bind":"127.0.0.1:9090","logger":"proxy","timestamp":1788549875870,"message":"Management API server started"}
```

`auth` reads `unauthenticated` when no token is set, and it is worth checking
after a config change. Note the `debug = true`: the default log level is
`warn`, so on a normal deployment this line is not printed at all and the way
to confirm the token is a request without one, which should be a `401`.

The server carries its own deadlines — 5s for request headers, 30s for the body,
60s for a response, 120s idle — so a client that opens a connection and dribbles
bytes cannot hold a goroutine indefinitely.

## GET /stats

```bash
curl -s -H "Authorization: Bearer a-long-random-string" http://127.0.0.1:9090/stats
```

```json
{
  "started_at": "2026-09-04T09:00:00Z",
  "uptime_seconds": 7200,
  "total_connections": 11,
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
  "users": {
    "alice": {
      "connections": 8,
      "bytes_in": 1048576,
      "bytes_out": 2097152,
      "last_seen": "2026-09-04T10:58:12Z",
      "quota_used": 3145728
    },
    "bob": {
      "connections": 3,
      "bytes_in": 524288,
      "bytes_out": 1048576,
      "last_seen": "2026-09-04T10:59:41Z",
      "quota_used": 1572864,
      "quota": 53687091200,
      "quota_remaining": 53685518336,
      "quota_reset": "monthly"
    }
  }
}
```

Top level:

| Field | Notes |
|---|---|
| `started_at`, `uptime_seconds` | Process start and age. |
| `total_connections` | Sum of every user's live connections. |
| `features` | Capability names — see below. Always an array, never `null`. |
| `throttle` | Present only when `[throttle] max-connections` is set. |
| `listeners`, `obfuscated` | Present only when at least one `[[listener]]` is configured. |
| `users` | Keyed by secret name. |

Timestamps are RFC3339 in the server's own zone, not forced to UTC, and carry
sub-second precision. A client parsing `started_at`, `last_seen` or `expires_at`
has to accept an offset such as `+03:30`, not just a trailing `Z`.

Per user:

| Field | Present | Notes |
|---|---|---|
| `connections` | always | Live connections right now. |
| `bytes_in`, `bytes_out` | always | Relayed bytes since process start. |
| `last_seen` | always | `null` for a user who has never connected. |
| `quota_used` | always | Bytes counted against the current quota period. |
| `quota`, `quota_remaining` | when a quota is set | Bytes. `quota_remaining` floors at 0. |
| `quota_cutoffs` | when non-zero | Streams ended by reaching the quota since the process started. |
| `quota_reset` | when not `none` | Currently only `"monthly"`. |
| `expires_at` | when an expiry is set | RFC3339. |
| `disabled` | when true | Omitted when false. |
| `speed_limit` | when a speed limit is set | Bytes per second. |
| `throttled_ms` | when non-zero | Milliseconds this user's connections have spent held to their speed limit. See [[Limits-and-Quotas]]. |
| `ip_limit` | when an address limit is set | How many places the user may be at once. |
| `active_ips` | when non-zero | How many places the user counts as being in right now: the addresses of their live connections here plus any reported from elsewhere. A count, never gated. |
| `ip_limit_refused` | when non-zero | Connections turned away for arriving from one place too many. |
| `ad_tag_skipped` | when non-zero | Ad-tagged streams that took the direct path because their transport has no middle-proxy reframer. By design. |
| `ad_tag_failed` | when non-zero | Ad-tagged streams that took the direct path because the middle proxy could not be reached or refused them. Not by design: this is the sponsored channel going missing — except for a few right after a restart, while the middle-proxy config loads. |
| `connected_ips`, `last_ip` | only with `track-client-ips` | See below. |
| `external_ips`, `external_expires_at` | only with `track-client-ips` | The addresses a panel reported the user present at elsewhere, and when that report lapses. See [external addresses](#external-addresses-secretsnameexternal-ips). |

Two behaviours that catch people out:

- A counter bucket is never deleted. Removing a user through
  `DELETE /secrets` leaves their row in `users` until the process restarts, so a
  panel should treat `/secrets` as the roster and `/stats` as the meter.
- An omitted field and an idle user look identical. `connected_ips` is absent
  both when tracking is off and when the user has no live connection; the same
  is true of every `omitempty` field above. Read `features` to learn what the
  binary can do, and the config to learn what it was asked to do.

Cross-reference: [[Limits-and-Quotas]] for what the quota fields mean,
[[Monitoring]] for Prometheus and statsd, which are a separate surface.

## The features array

`features` is a sorted list of capability names the **binary** supports:

```text
client-ip-activity  client-ips  faketls  ip-limits  kick  listeners  quota-ceiling  quota-reset  secret-modes  secret-read  secrets-api  speed-directions  speed-limits  web-relay  web-relay-watch
```

| Name | Means |
|---|---|
| `client-ip-activity` | `connected_ips_last_seen` accompanies `connected_ips` wherever it appears: when each address last moved a byte, gated exactly as the addresses are. |
| `client-ips` | The binary understands `track-client-ips`, and `connected_ips`/`last_ip` may appear when it is on. |
| `faketls` | The FakeTLS handshake is served. |
| `ip-limits` | `ip_limit` is accepted on `[secret-limits.<name>]` and the secrets API, `/stats` reports `ip_limit`, `active_ips` and `ip_limit_refused`, and `/secrets/{name}/external-ips` is served. |
| `kick` | `POST /secrets/{name}/kick` closes a user's live streams from the named places. |
| `listeners` | The `[[listener]]` table is honoured and `/stats` reports each socket. |
| `quota-ceiling` | The quota is enforced on the data path — a stream ends at the byte that reaches it and a five-second sweep closes the idle ones — rather than only refusing the next connection. |
| `quota-reset` | `POST /secrets/{name}/reset-quota` is served. |
| `secret-modes` | The `dd` and plain secret forms parse and serve. |
| `secret-read` | `GET /secrets/{name}` is served. |
| `secrets-api` | The `GET`/`PUT`/`POST`/`DELETE` `/secrets` routes are served. |
| `speed-directions` | `speed-up` and `speed-down` (`speed_up`/`speed_down` on the API) cap each direction on its own bucket, read back as `speed_limit_up`/`speed_limit_down`. |
| `speed-limits` | `speed` is accepted on `[secret-limits.<name>]` and the secrets API, and `/stats` reports `speed_limit` and `throttled_ms`. |
| `web-relay` | This binary carries the WEB transport: the `web-relay` and `generate-web-key` subcommands and the `[web]` table. |
| `web-relay-watch` | The relay follows its config file by itself; a changed `[secrets]` table is applied within seconds of the write settling. |

It exists so a caller can check a capability before using it, instead of parsing
a version string and maintaining a table of which release added what. That
matters most for a panel driving several proxies of different vintages: one
`GET /stats` tells it whether to render the WEB settings, offer the client-IP
switch, or fall back.

Three rules make it dependable, and they are a public contract:

- names are never renamed or removed, only appended;
- a name is only added once the capability is actually in the binary;
- the list is sorted, so the response is byte-stable across restarts.

`web-relay` is advertised by the proxy even though the proxy does not serve that
transport. That is deliberate: the relay is a second process a panel may not
have started yet, and the proxy answering `/stats` is the one component it can
always ask. See [[WEB-Proxy-Setup]].

`client-ips` says the option is understood, not that it is enabled. Nothing in
the response tells you whether an operator turned it on, which is intentional.

## Client addresses

New in v1.3.0, and **off by default**. With `track-client-ips = true`, each user
on `/stats` and `/secrets` also reports the addresses behind their connections:

```json
"alice": {
  "connections": 2,
  "connected_ips": ["198.51.100.7", "203.0.113.44"],
  "connected_ips_last_seen": {
    "198.51.100.7": "2026-09-07T10:41:58Z",
    "203.0.113.44": "2026-09-07T10:42:03Z"
  },
  "last_ip": "203.0.113.44"
}
```

`connected_ips` is the set of distinct addresses holding a live connection right
now, deduplicated and sorted. It is derived from the connection registry rather
than counted separately, so it cannot drift from the `connections` beside it,
and an entry disappears when its connection ends. It deduplicates on the full
address, while `ip-limit` counts an IPv6 /64 as one place: two entries in one
/64 are one place to the limit, so a caller counting devices from this array
must collapse to the /64 itself to agree with the refusal. `connected_ips_last_seen` is,
for each of those addresses, the second a stream from it last moved a byte —
the latest across the streams sharing the address, so a device that fell silent
reads as silent while its sibling on the same address talks. It is stamped to
the second, on the data path, and gated exactly as the addresses are. `last_ip`
is the address of the most recently admitted connection and outlives that
connection.

**Why the default is off, and why leaving it off is the right call for most
deployments.** This is a circumvention proxy. The people using it are frequently
the reason it exists, and an operator's answer to "who connected from where" is
also the answer available to whoever ends up with the server — by seizure,
compromise or subpoena. `connected_ips` adds no retention on its own, since
those addresses are already held for the life of the connection. `last_ip` does:
it survives the connection it came from, so a deployment that never asks for
either never accumulates one.

Nothing here is written to disk in any form. `usage-state-file` persists quota
counters only, so no address survives a restart. Turn this on for a specific,
time-boxed reason — chasing an abuse report, debugging a NAT — and turn it back
off. It is not a monitoring default. The setting is not hot-appliable, so each
toggle costs a proxy restart, which is a small friction worth keeping.

The recording is gated at write time, not at read time: with the option off the
proxy never stores `last_ip` at all, so switching it on does not reveal a
backlog. Both `connections` and `last_seen` are ungated, because they are not
addresses — knowing a user has two connections says nothing about where they
are.

Behind a front proxy, both report what the PROXY header carried, which is the
client's real address. That is what makes them useful for a WEB deployment,
where every connection otherwise arrives from `127.0.0.1`. See
[[WEB-Proxy-Setup]] and [[Security]].

## Managing secrets at runtime

| Method and path | Action |
|---|---|
| `GET /secrets` | List every secret with its live counters. |
| `GET /secrets/{name}` | One entry of that list, by name — the same object the list would hold for that user, from the same snapshot. |
| `POST /secrets` | Add or replace one secret. |
| `PUT /secrets` | Replace the entire set. |
| `DELETE /secrets/{name}` | Remove one. |
| `POST /secrets/{name}/reset-quota` | Zero that secret's used-bytes counter and restart its quota period. |
| `GET /secrets/{name}/external-ips` | That user's address view: limit, count, and the addresses when tracking is on. |
| `PUT /secrets/{name}/external-ips` | Report the addresses the user holds on other systems, so the address limit spans them. |
| `DELETE /secrets/{name}/external-ips` | Clear that report. |

### GET /secrets

```bash
curl -s -H "Authorization: Bearer a-long-random-string" http://127.0.0.1:9090/secrets
```

```json
{
  "secrets": [
    {
      "name": "alice",
      "secret": "7jZ6GJruGPoxwZAFTv1KjpVzdG9yYWdlLmdvb2dsZWFwaXMuY29t",
      "host": "storage.googleapis.com",
      "mode": "ee",
      "connections": 8,
      "last_seen": "2026-09-04T10:58:12Z"
    },
    {
      "name": "bob",
      "secret": "7gEjRWeJq83vASNFZ4mrzZVzdG9yYWdlLmdvb2dsZWFwaXMuY29t",
      "host": "storage.googleapis.com",
      "mode": "ee",
      "quota": 53687091200,
      "quota_used": 1572864,
      "quota_remaining": 53685518336,
      "quota_reset": "monthly",
      "connections": 3,
      "last_seen": "2026-09-04T10:59:41Z"
    }
  ]
}
```

The list is sorted by name.

| Field | Present | Notes |
|---|---|---|
| `name` | always | The `[secrets]` key. |
| `secret` | always | Base64 (RFC 4648 URL alphabet, unpadded). Note this is **not** the hex you wrote in the file — it is the same bytes in the other spelling, and both parse on input. |
| `host` | always | The fronting hostname. Empty string for a `dd` or plain secret, which carry none. |
| `mode` | always | `"ee"`, `"dd"` or `"plain"` — the wire form this secret serialises to. |
| `ad_tag` | when a per-secret override is set | Hex. |
| `effective_ad_tag` | when any tag applies | Hex, after global fallback. |
| `unserved` | when true | No configured listener honours this secret's form — a `dd` or plain secret on a proxy with no `[[listener]]`. |
| `quota`, `quota_used`, `quota_remaining` | when a quota is set | Bytes. Unlike `/stats`, `quota_used` here appears only alongside a quota. |
| `quota_reset` | when not `none` | |
| `expires_at` | when an expiry is set | |
| `disabled` | when true | |
| `speed_limit` | when a speed limit is set (v1.6.0) | Bytes per second; set as `speed` with a human spelling. |
| `ip_limit` | when an address limit is set (v1.7.0) | How many places the user may be at once; set as `ip_limit`, an integer. |
| `active_ips` | when non-zero (v1.7.0) | How many places the user counts as being in right now. Never gated. |
| `connections` | always (v1.3.0) | Live connections. `0` for a secret nobody has used. |
| `last_seen` | always (v1.3.0) | `null` when never connected. |
| `connected_ips`, `last_ip` | only with `track-client-ips` (v1.3.0) | Same gate as `/stats`. |
| `external_ips`, `external_expires_at` | only with `track-client-ips` (v1.7.0) | Same gate. The user's reported addresses elsewhere and when the report lapses. |

`connections` and `last_seen` were added so a caller rendering one user does not
have to fetch and filter the whole of `/stats`. They are the same counters
`/stats` reads, not a second tally.

`unserved` is reported rather than refused. Storing a `dd` secret on a proxy
with no obfuscated2 listener is valid — the secret simply has no door yet — and
making it an error would let one odd client take an inbound offline. It is still
the kind of thing an operator wants surfaced. See [[Connection-Types]].

### POST /secrets

Add a user, or change one that exists:

```bash
curl -s -X POST -H "Authorization: Bearer a-long-random-string" -H "Content-Type: application/json" -d '{"name":"carol","secret":"ee9f2b6d1c4a7e830f5d21b8c60e4a179573746f726167652e676f6f676c65617069732e636f6d","quota":"20GB","quota_reset":"monthly","expires":"2026-12-31"}' http://127.0.0.1:9090/secrets
```

```json
{"status": "ok"}
```

Fields: `name` and `secret` are required; `ad_tag`, `quota`, `quota_reset`,
`expires`, `disabled`, `speed` and `ip_limit` are optional. `secret` accepts hex or base64
in any of the three forms. `quota` takes a human size (`"20GB"`, `"500MiB"` —
base-2 units, so `GB` is 2^30) or a bare integer byte count. `expires` takes
RFC3339 or `YYYY-MM-DD`; a date-only value means midnight UTC. `quota_reset` is
`"none"` or `"monthly"`. `speed` takes a rate — `"5mbit"`, `"500kbit"`,
`"1MB/s"` — with the same spellings and the same floor as the config file, and
reaches the user's live connections at once. `ip_limit` is an integer, how many
places the user may be at once; zero or absent is unlimited, and a negative
value is `400`. Both are explained on [[Limits-and-Quotas]].

**This route replaces the whole entry, it does not merge.** Re-posting `carol`
without `quota` clears her quota; without `ad_tag`, clears her ad-tag override.
Send the complete desired state every time, or read `GET /secrets` first.

Note the asymmetry between what you send and what you read back: `quota` goes in
as a string and comes out as an integer byte count, `speed` goes in as a string
and comes out as `speed_limit` in bytes per second, and `expires` goes in but
`expires_at` comes out.

### PUT /secrets

Replace the entire set in one atomic swap. Anything absent from the body is
gone:

```bash
curl -s -X PUT -H "Authorization: Bearer a-long-random-string" -H "Content-Type: application/json" -d '{"secrets":{"alice":{"secret":"ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"},"bob":{"secret":"ee0123456789abcdef0123456789abcd9573746f726167652e676f6f676c65617069732e636f6d","quota":"50GB","quota_reset":"monthly"}},"ad_tag":"0123456789abcdef0123456789abcdef"}' http://127.0.0.1:9090/secrets
```

Omitting the top-level `ad_tag` **clears the global ad-tag**, and any per-secret
override not listed is dropped too. This is the route to use when your source of
truth renders the full roster anyway; use `POST` for incremental edits.

Every per-secret limit travels in the same object as the secret, under the JSON
spelling of its config key: `quota`, `quota_reset`, `expires`, `disabled`,
`speed`, `speed_up`, `speed_down` and `ip_limit`. A limit absent from the body is
absent from the proxy after the swap — this route replaces, it does not merge —
so a panel that sets a speed through the file must send it here too. Speeds and
the quota are strings in the config file's grammar; `ip_limit` is a number.

### DELETE and reset-quota

```bash
curl -s -X DELETE -H "Authorization: Bearer a-long-random-string" http://127.0.0.1:9090/secrets/carol
```

`404` for an unknown name, `409` if it would empty the set — the proxy always
keeps at least one secret, because a proxy with none has nothing to serve and
nothing to front.

```bash
curl -s -X POST -H "Authorization: Bearer a-long-random-string" http://127.0.0.1:9090/secrets/bob/reset-quota
```

That zeroes `quota_used` and restarts the monthly period from now. `404` for an
unknown name.

### Kick: `POST /secrets/{name}/kick`

New with the `kick` feature, for a panel that decides which of a user's devices
is one too many itself and enforces that here:

```bash
curl -s -X POST -H "Authorization: Bearer a-long-random-string" -H "Content-Type: application/json" -d '{"ips":["203.0.113.9","2001:db8:1:2::1"]}' http://127.0.0.1:9090/secrets/alice/kick
```

```json
{"closed": 3}
```

Every live stream alice holds from one of those places is closed, and her
streams from every other place keep running. A place is matched at the unit the
address limit counts: an IPv6 address kicks its whole /64, so the device that
rotated its low bits since the panel last saw it is still the device that was
kicked. `ips` is one or more literal addresses, no prefixes, no zones. A place
the user is not at is a kick of zero, not an error; a malformed body is `400`
and an unknown user `404`. The kicked client sees its connection drop and will
reconnect; whether that reconnect is admitted is the address limit's business,
not the kick's.

### External addresses: `/secrets/{name}/external-ips`

New in v1.7.0, for a panel that enforces one address limit across several
systems. The proxy counts a user's places as the addresses of their live
connections here plus whatever the panel reports them holding elsewhere — on a
VPN, over SSH, on another proxy — and this route is how the panel reports it.

| Method | Body | Answer |
|---|---|---|
| `GET` | | The user's address view: `name`, `ip_limit`, `active_ips`, and — only with `track-client-ips` — `connected_ips`, `external_ips` and `external_expires_at`. |
| `PUT` | `{"ips":["198.51.100.7","2001:db8::1"],"ttl":"90s"}` | Replaces the reported set whole and answers with the same view, so the panel sees what will be enforced. |
| `DELETE` | | Clears the reported set. |

`ips` is at most 64 literal addresses: no prefixes, no zones, and an IPv6
address counts as its /64. `ttl` is a Go duration in `(0, 1h]`; omitted, it is
`2m`. Every entry of one report shares one expiry, and the panel is expected to
`PUT` again well inside it — a report is a heartbeat, not a registration. When
it lapses the proxy enforces the limit on what it can see itself, which is the
right failure for a panel that has gone away. A malformed report is `400` and
changes nothing; an unknown user is `404` on every verb.

The reported addresses are held in memory only, never written to disk or to
the log, and read back only with `track-client-ips`, exactly as `connected_ips`
is; the counts always come back. What counts as a place, and how the limit
behaves when a device changes networks, is on [[Limits-and-Quotas]].

### What a mutation does to live connections

`POST`, `PUT` and `DELETE` all go through the same atomic swap as a file reload:

- a **new** secret starts working immediately;
- a **re-keyed or removed** secret has its live connections closed, because the
  key they were admitted with no longer exists;
- an **ad-tag-only** change leaves connections running — the tag affects the
  routing of new connections only;
- **disabling** a secret, or giving it an expiry already in the past, closes its
  live connections immediately;
- a **quota** lowered to or below what the user has already used closes their
  live connections too, and a quota reached mid-stream ends the stream at the
  byte that reaches it (v1.8.0; before, a quota was checked only at admission);
- every other user stays connected, and all counters carry over.

`reset-quota` is the exception: it touches one counter and no connection at all.
An over-quota user is not reconnected by it, but their next attempt is admitted.

One swap is refused outright: a set that leaves `bind-to` with no `ee` secret
*and* no `[domain-fronting] host` is rejected, and the previous set stays live.
`bind-to` is permanently FakeTLS-only, and without a fronting host it would have
to close every failed ClientHello instead of passing it to a real site — which
is precisely the distinguisher domain fronting exists to remove. See
[[Security]].

### Mutations are in-memory only

Nothing these routes do is written back to the config file. A later
`POST /reload`, or a restart, re-reads the file and overrides them. Treat the
file as the source of truth and the API as a live override; a panel that owns
the roster should write the file first and then call `/reload`.

One practical consequence: `mtg-proxy access` reads the config file, not the
API. A user added only through `POST /secrets` gets no link from `access` until
they are also in the file.

## The ad-tag routes

```bash
curl -s -H "Authorization: Bearer a-long-random-string" http://127.0.0.1:9090/adtag
```

```json
{"ad_tag": "0123456789abcdef0123456789abcdef"}
```

`{"ad_tag": null}` when none is set.

```bash
curl -s -X PUT -H "Authorization: Bearer a-long-random-string" -H "Content-Type: application/json" -d '{"ad_tag":"0123456789abcdef0123456789abcdef"}' http://127.0.0.1:9090/adtag
```

```bash
curl -s -X DELETE -H "Authorization: Bearer a-long-random-string" http://127.0.0.1:9090/adtag
```

The tag must be exactly 16 bytes, 32 hex characters. `PUT` with an empty
`ad_tag` is a `400` that tells you to use `DELETE` instead, so a serialisation
bug that drops the value cannot silently unset a tag you are paying attention
to. Neither route closes any connection.

Per-secret overrides live in `[secret-ad-tags]` in the file, or in the `ad_tag`
field of the `/secrets` routes.

## Errors and status codes

| Status | When |
|---|---|
| `400` | Malformed JSON, an unknown JSON field, an invalid secret, a bad ad-tag, an unparseable quota, speed or expiry, a kick naming no valid address, or a swap that would leave nothing to front. |
| `401` | `api-token` is set and the `Authorization` header is missing or wrong. |
| `404` | Unknown secret name on `GET` or `DELETE /secrets/{name}`, `/reset-quota`, `/kick` or `/external-ips`; unknown path. |
| `405` | Wrong method — `POST /stats`, or anything but `POST` on `/reload`. |
| `409` | `DELETE /secrets/{name}` would remove the last secret. |
| `500` | `POST /reload` could not read, parse or validate the config file. |
| `503` | `POST /reload` on a proxy started without a config file. |

There are two shapes of error body, which matters if you are writing a client.
The `/secrets` and `/adtag` routes return JSON:

```json
{"error": "cannot delete the last secret"}
```

The `/reload` failures and the `401` are plain text from Go's `http.Error` —
the `401` body is the single word `unauthorized`, alongside a
`WWW-Authenticate: Bearer` header. A `405` carries an `Allow` header naming
what the path does take (`POST` for `/reload`, `GET, HEAD` for `/stats`).

Request bodies are decoded with unknown fields **disallowed**. Sending an extra
key — a field from a newer release, a stray `id` your ORM added — is a `400`:

```json
{"error": "invalid request body: json: unknown field \"id\""}
```

That is a deliberate trade: a typo in a field name fails loudly instead of
silently not applying the limit you meant to set. Check `features` before
sending anything new.

## Hot reload

```bash
curl -s -X POST -H "Authorization: Bearer a-long-random-string" http://127.0.0.1:9090/reload
```

```json
{"status": "ok"}
```

This re-reads the same config file path given to `mtg-proxy run` and swaps the
secret set in atomically, with exactly the connection semantics listed above.

**Hot-applied:**

- `[secrets]`
- `ad-tag`
- `[secret-ad-tags]`
- `[secret-limits]`

**Not hot-applied.** Everything else needs a restart: `bind-to`, `api-bind-to`,
`api-token`, `[[listener]]` blocks, `[domain-fronting]`, `[network]`,
`[throttle]`, `track-client-ips`, `usage-state-file` and the whole `[web]`
table. A reload does not report these as unchanged or refused — it reads the
whole file, validates it, and applies only the four items above. If you edited
`bind-to` and called `/reload`, the call succeeds and the port does not move.

The reload path runs the same parse, environment overlay and validation as
startup, which has two consequences. An invalid file is a `500` and the current
set keeps serving — a proxy that emptied its roster because someone saved a
broken file is far worse than a stale one. And environment overrides are
re-applied on every read, so a `SECRET` or `TAG` pinned in the environment
survives a reload rather than being replaced by whatever the file says. See
[[Configuration]].

`POST /reload` returns `503` when the proxy was started with `simple-run`, which
takes flags instead of a file: there is no source to re-read.

## Reloading the WEB relay

The WEB relay is a second process of the same binary reading the same file. It
does not share the management listener — putting an HTTP management surface on a
process whose entire security argument is that it presents one ordinary hostname
to the internet would defeat the point. Instead it **watches the file**: a
changed `[secrets]` table is applied by itself within a few seconds of the write
settling. Add a user to the file and there is nothing to tell the relay.

A `SIGHUP` applies a change immediately rather than on the next look:

```bash
kill -HUP <relay-pid>
```

If you run the relay under systemd, the same thing through a unit whose
`ExecReload` sends `SIGHUP` — the repository ships a Caddy snippet and a compose
file under `contrib/web-relay/`, but no unit file, so this is one you write:

```bash
systemctl reload mtg-proxy-web-relay
```

The file is the only thing the relay reads. A user added through this API and
never written to the file is unknown to the relay, and their WEB link is
answered by the cover site. The API is in-memory by design (see above); write
the file.

Only the secret set reloads. Live sessions keep running, a newly added secret is
recognised on its next page load, and a removed one stops being recognised.

Any other change under `[web]` — the host, the bind address, the backend, the
token key, the cover site, the client-IP source, the session and frame limits,
`stats-bind-to` — is refused **whole** with
`[web] changed in a way that needs a restart`, and the profile set is left
alone. So is a change to the backend `[[listener]]`'s
`proxy-protocol` flag, which the relay reads from that stanza rather than from a
setting of its own so the two processes cannot disagree about what the socket
between them speaks. Half-applying a changed file is how a relay ends up in a
state no configuration describes.

A reload that cannot read or validate the file also keeps the running set. An
emptied registry would serve the cover site to every real user while reporting
nothing wrong — indistinguishable, from the client's side, from the censorship
the relay exists to get around.

Refusals are counted, so "my SIGHUP did nothing" is distinguishable from "my
SIGHUP was never delivered". If you set `[web] stats-bind-to`, the relay's own
stats socket reports `reloads` (successes), `reload_failures` and `last_reload`
(the time of the last success). Every refusal counts, an unparseable file
included; a file the relay refused counts once and is not tried again until it
changes. A file change that left the profiles alone is not a reload and moves
nothing, whereas a `SIGHUP` that changed nothing still counts as one — the
operator who sent it is asking whether it landed.

That socket must be a loopback **IP literal**. The relay refuses to start on
anything else, and refuses names — `localhost` included — because a name can
resolve somewhere else tomorrow, and the one thing this socket must never be is
reachable from outside the host. It is also deliberately a second socket rather
than a path on the public origin: everything on that origin without a credential
the relay minted gets the cover site, so an endpoint there would be a
fingerprint however well it was gated. See [[Monitoring]] and
[[WEB-Proxy-Setup]].

**Windows has no SIGHUP.** Go defines the constant but nothing delivers it, so
the Windows build registers no reload signal at all rather than advertising one
that never fires. The file watcher runs there as everywhere, so a Windows relay
follows the file by itself; it just cannot be hurried. A deployment running both
processes reloads the proxy with `POST /reload` and lets the relay follow the
file — or sends it `SIGHUP` to make that immediate.

## See also 🔗

- [[Configuration]] — every key, with defaults.
- [[Limits-and-Quotas]] — quotas, expiry, the disabled switch and throttling.
- [[Connection-Types]] — the three doors one secret opens.
- [[Monitoring]] — Prometheus, statsd and the relay stats socket.
- [[Security]] — what to harden, and why `track-client-ips` is off.
- [[Troubleshooting]] — when a reload does not do what you expected.
