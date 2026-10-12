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
  - [Per-address usage](#per-address-usage-get-secretsnameclients)
  - [Bans](#bans-secretsnamebans)
  - [Kick, ban or re-key](#kick-ban-or-re-key)
- [Rotating a secret with an overlap](#rotating-a-secret-with-an-overlap)
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
| `faketls_handshake` | Present only once the FakeTLS door has counted something. What the door decided about each `ee` hello, and whether the handshake budget is enforcing; see [[Monitoring]]. A top-level object: nothing about it is under `users`. |
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
| `throttled_ms` | when non-zero | Milliseconds this user's connections have spent held to their speed limits, and to the per-address limits (`client-speed`, `client-fair`) of the addresses they came from. See [[Limits-and-Quotas]]. |
| `ip_limit` | when an address limit is set | How many places the user may be at once. |
| `active_ips` | when non-zero | How many places the user counts as being in right now: the addresses of their live connections here plus any reported from elsewhere. A count, never gated. |
| `ip_limit_refused` | when non-zero | Connections turned away for arriving from one place too many. |
| `client_conns` | when `client-conns` is set | How many live connections one address may hold to this secret. |
| `client_conns_refused` | when non-zero | Connections turned away for arriving from an address that already held `client_conns` of them. |
| `client_speed_limit` | when `client-speed` is set | The per-address ceiling, in bytes per second. |
| `client_fair` | when true | The user's speed limits are divided among the addresses they connect from. |
| `clients` | when non-zero | How many addresses the per-address table holds an entry for, live and idle, the shared rest entry not counted. A count, never gated. The addresses are on [`GET /secrets/{name}/clients`](#per-address-usage-get-secretsnameclients). |
| `clients_overflow` | when non-zero | Connections sent to the rest entry because the table had no room for their address. |
| `ad_tag_skipped` | when non-zero | Ad-tagged streams that took the direct path because their transport has no middle-proxy reframer. By design. |
| `ad_tag_failed` | when non-zero | Ad-tagged streams that took the direct path because the middle proxy could not be reached or refused them. Not by design: this is the sponsored channel going missing — except for a few right after a restart, while the middle-proxy config loads. |
| `connected_ips`, `last_ip` | only with `track-client-ips` | See below. |
| `external_ips`, `external_expires_at` | only with `track-client-ips` | The addresses a panel reported the user present at elsewhere, and when that report lapses. See [external addresses](#external-addresses-secretsnameexternal-ips). |
| `retiring_keys` | while the user has an unexpired previous key (`secret-rotation`) | How many previous keys of the secret are still accepted. See [Rotating a secret with an overlap](#rotating-a-secret-with-an-overlap). |
| `retiring_until` | with `retiring_keys` | The latest `until` among them, in UTC: when the last old link stops working. |
| `retiring_connections` | with `retiring_keys`, when non-zero | Live connections of the user on a key that is not its current one. |
| `retiring_last_seen` | with `retiring_keys`, once a connection came in on a previous key during this overlap | When the last one did, in UTC. |

The per-address fields are scalars inside the user object. Nothing per-address
is ever a key under `users`, which a panel bills as one client per key; the
addresses themselves are on their own endpoint.

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
client-bans  client-ip-activity  client-ips  client-limits  client-stats  faketls  handshake-budget  ip-limits  kick  listeners  quota-ceiling  quota-reset  secret-modes  secret-read  secret-rotation  secrets-api  speed-directions  speed-limits  web-relay  web-relay-watch
```

| Name | Means |
|---|---|
| `client-bans` | `POST` and `GET /secrets/{name}/bans` and `DELETE /secrets/{name}/bans/{address}` are served, a banned address is turned away at every door as a wrong secret is, and `/clients` rows carry `banned_until`. |
| `client-ip-activity` | `connected_ips_last_seen` accompanies `connected_ips` wherever it appears: when each address last moved a byte, gated exactly as the addresses are. |
| `client-ips` | The binary understands `track-client-ips`, and `connected_ips`/`last_ip` may appear when it is on. |
| `client-limits` | `client-conns`, `client-speed` and `client-fair` are honoured in `[secret-limits.<name>]`, and as `client_conns`, `client_speed` and `client_fair` on the secrets API. `/stats` reads them back as `client_conns`, `client_speed_limit` and `client_fair`, and counts `client_conns_refused`. |
| `client-stats` | `GET /secrets/{name}/clients` is served, and `/stats` carries `clients` and `clients_overflow` inside the user object. |
| `faketls` | The FakeTLS handshake is served. |
| `handshake-budget` | The FakeTLS door bounds the CPU it spends scanning hellos no hint matched, `[defense.handshake-budget]` is honoured, and `/stats` reports the door's counters as the top-level `faketls_handshake` object once it has counted something. |
| `ip-limits` | `ip_limit` is accepted on `[secret-limits.<name>]` and the secrets API, `/stats` reports `ip_limit`, `active_ips` and `ip_limit_refused`, and `/secrets/{name}/external-ips` is served. |
| `kick` | `POST /secrets/{name}/kick` closes a user's live streams from the named places. |
| `listeners` | The `[[listener]]` table is honoured and `/stats` reports each socket. |
| `quota-ceiling` | The quota is enforced on the data path — a stream ends at the byte that reaches it and a five-second sweep closes the idle ones — rather than only refusing the next connection. |
| `quota-reset` | `POST /secrets/{name}/reset-quota` is served. |
| `secret-modes` | The `dd` and plain secret forms parse and serve. |
| `secret-read` | `GET /secrets/{name}` is served. |
| `secret-rotation` | `[[retiring-secret]]` is honoured, the binary has `mtg-proxy rotate-secret`, and `/stats` and `GET /secrets` may carry `retiring_keys`, `retiring_until`, `retiring_connections` and `retiring_last_seen` inside a user's own object. `rotate-secret --reload` asks for it before it writes anything. |
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
either never accumulates one. (That is about these two fields: the ee handshake
budget keeps a separate anonymous per-address bucket in memory whatever
`track-client-ips` says; see *Client addresses* in [[Security]].)

With tracking on, the proxy also keeps every address a secret is used from in
its per-address table, with what that address moved, until ten minutes after
its last connection closes, and lists it on
[`GET /secrets/{name}/clients`](#per-address-usage-get-secretsnameclients) for up
to about eleven minutes. That reaches further back than `connected_ips`. A
secret with a per-address control keeps such entries even with tracking off,
and then reports only counts.

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
| `POST /secrets/{name}/kick` | Close that user's live streams from the named places. |
| `GET /secrets/{name}/clients` | Per-address usage of one secret: counts always, the addresses only with `track-client-ips`. |
| `POST /secrets/{name}/bans` | Ban places from one secret for a while, closing their live streams. |
| `GET /secrets/{name}/bans` | That secret's bans: a count always, the addresses only with `track-client-ips`. |
| `DELETE /secrets/{name}/bans/{address}` | Lift one ban. |

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
| `client_conns` | when `client-conns` is set (`client-limits`) | How many live connections one address may hold to this secret; set as `client_conns`, an integer. |
| `client_speed_limit` | when `client-speed` is set (`client-limits`) | The per-address ceiling in bytes per second; set as `client_speed` with a human spelling. |
| `client_fair` | when true (`client-limits`) | The secret's speed limits are divided among its addresses; set as `client_fair`. |
| `connections` | always (v1.3.0) | Live connections. `0` for a secret nobody has used. |
| `last_seen` | always (v1.3.0) | `null` when never connected. |
| `connected_ips`, `last_ip` | only with `track-client-ips` (v1.3.0) | Same gate as `/stats`. |
| `external_ips`, `external_expires_at` | only with `track-client-ips` (v1.7.0) | Same gate. The user's reported addresses elsewhere and when the report lapses. |
| `retiring_keys`, `retiring_until`, `retiring_connections`, `retiring_last_seen` | while the secret has an unexpired previous key (`secret-rotation`) | The same four fields as on `/stats`, from the same set and counters. Never a key. See [Rotating a secret with an overlap](#rotating-a-secret-with-an-overlap). |

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

The per-address controls (feature `client-limits`) are three more optional
fields. `client_conns` is an integer, how many live connections one address may
hold to the secret; zero or absent is no cap, and a negative value is `400`.
`client_speed` is a rate in the same spelling as `speed`, a ceiling on one
address; absent is no ceiling, and `"0"` or a value under `64kbit` is `400`.
`client_fair` is `true` or `false`, and `true` needs `speed`, `speed_up` or
`speed_down` in the same request, or the request is `400`: this route replaces
every limit, so a speed set earlier is gone by the time it applies. They are
read back as `client_conns`, `client_speed_limit` and `client_fair`. What they
do is on [[Configuration]], under *Per-address controls*.

**This route replaces the whole entry, it does not merge.** Re-posting `carol`
without `quota` clears her quota; without `ad_tag`, clears her ad-tag override;
without `client_conns`, `client_speed` or `client_fair`, clears those. Send the
complete desired state every time, or read `GET /secrets` first.

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
`speed`, `speed_up`, `speed_down`, `ip_limit`, `client_conns`, `client_speed`
and `client_fair`. A limit absent from the body is
absent from the proxy after the swap — this route replaces, it does not merge —
so a panel that sets a speed through the file must send it here too. Speeds and
the quota are strings in the config file's grammar; `ip_limit` and
`client_conns` are numbers, `client_fair` a boolean.

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

Kick takes addresses, not prefixes. To kick an IPv6 row of
[`GET /secrets/{name}/clients`](#per-address-usage-get-secretsnameclients),
which is spelled as a /64 (`2001:db8:1:2::/64`), send its prefix address without
the `/64` (`2001:db8:1:2::`), or any address inside it; the `/64` form itself is
`400`. To keep a place out after the kick, ban it instead (below).

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

### Per-address usage: `GET /secrets/{name}/clients`

New with the `client-stats` feature. One secret's usage per source address: what
each address moved, how many connections it holds and the per-address rates in
force on it. It is an endpoint of its own because `/stats` cannot carry it:
every key under `users` there is billed as a client.

```bash
curl -s -H "Authorization: Bearer a-long-random-string" "http://127.0.0.1:9090/secrets/alice/clients?limit=50"
```

With `track-client-ips` on, for a secret with `client-speed = "2mbit"`:

```json
{
  "total": 3,
  "overflow": 0,
  "tracking": true,
  "rest": {
    "connections": 2,
    "bytes_in": 81920,
    "bytes_out": 1572864,
    "first_seen": "2026-10-07T08:02:11Z",
    "last_seen": "2026-10-07T10:42:05Z"
  },
  "clients": [
    {
      "address": "203.0.113.44",
      "connections": 6,
      "bytes_in": 10485760,
      "bytes_out": 734003200,
      "throttled_ms": 412000,
      "first_seen": "2026-10-07T09:30:02Z",
      "last_seen": "2026-10-07T10:42:03Z",
      "speed_limit": 250000
    },
    {
      "address": "2001:db8:1:2::/64",
      "connections": 0,
      "bytes_in": 2097152,
      "bytes_out": 52428800,
      "first_seen": "2026-10-07T10:01:40Z",
      "last_seen": "2026-10-07T10:38:51Z",
      "speed_limit": 250000,
      "banned_until": "2026-10-07T11:38:51Z"
    },
    {
      "address": "198.51.100.7",
      "connections": 3,
      "bytes_in": 524288,
      "bytes_out": 4194304,
      "first_seen": "2026-10-07T10:20:13Z",
      "last_seen": "2026-10-07T10:42:01Z",
      "speed_limit": 250000
    }
  ]
}
```

With tracking off the answer is the counts and nothing else, whatever the
proxy holds:

```json
{"total": 3, "overflow": 0, "tracking": false}
```

| Field | Notes |
|---|---|
| `total` | How many addresses the secret holds an entry for, live and idle, the rest entry not counted. Every entry, not the page. Never gated. |
| `overflow` | Connections sent to the rest entry because the per-address table had no room for their address. Never gated. |
| `tracking` | Whether the proxy lists addresses at all (`track-client-ips`). |
| `rest` | Only with tracking, and only while the secret has a rest entry: the one entry shared by every peer that does not stand for one place (loopback, private and the like) and every address the table had no room for. No address, no ceiling. |
| `clients` | Only with tracking: one row per address, most bytes first (`bytes_in` plus `bytes_out`), ties by address. An empty array when there is none. |

Each row, and the `rest` object without its address:

| Field | Notes |
|---|---|
| `address` | An IPv4 address, or an IPv6 /64 in prefix form. |
| `connections` | Live connections from that address right now, from the same count `ip-limit` and `client-conns` read. For `rest`, the streams the rest entry governs. |
| `bytes_in`, `bytes_out` | What the address moved, from the client's side: `in` is what it sent. |
| `throttled_ms` | Milliseconds its streams spent held to its own per-address limits, the ceiling included. Absent when none. |
| `first_seen`, `last_seen` | When the entry was made, and the last second a connection from it opened or closed or a byte moved. UTC, whole seconds. |
| `speed_limit` | The tighter of its `client-speed` ceiling and its fair share of `speed`, in bytes per second. Absent when there is neither. |
| `speed_limit_up`, `speed_limit_down` | Its fair shares of `speed-up` and `speed-down`. Absent when there is none. |
| `banned_until` | When a ban of the address from this secret lapses (feature `client-bans`). Absent when it has none. |

`limit` is how many rows to return: 100 when absent, at most 1,000 whatever is
asked for, and `400` when it is not a whole number above zero. The rows are the
ones that moved the most, sorted before they are cut. An unknown secret is
`404`; a bad `limit` is `400` first.

How to read the list, and what it does and does not mean, is on [[Monitoring]].

### Bans: `/secrets/{name}/bans`

New with the `client-bans` feature. A ban refuses a place one secret for a
while and ends the streams the place holds now. It lives in memory only.

| Method | Body | Answer |
|---|---|---|
| `POST /secrets/{name}/bans` | `{"ips":["203.0.113.44"],"ttl":"1h","force":false}` | `{"banned":N,"closed":M}`, plus `addresses` with `track-client-ips`. |
| `GET /secrets/{name}/bans` | | `{"total":N,"tracking":false}`, or with `track-client-ips` the bans themselves. |
| `DELETE /secrets/{name}/bans/{address}` | | `{"removed":1}`, or `{"removed":0}` when the place had no ban. |

Ban two places from alice's secret for six hours:

```bash
curl -s -X POST -H "Authorization: Bearer a-long-random-string" -H "Content-Type: application/json" -d '{"ips":["203.0.113.44","2001:db8:1:2::5"],"ttl":"6h"}' http://127.0.0.1:9090/secrets/alice/bans
```

```json
{"banned": 2, "closed": 6, "addresses": ["2001:db8:1:2::/64", "203.0.113.44"]}
```

List them:

```bash
curl -s -H "Authorization: Bearer a-long-random-string" http://127.0.0.1:9090/secrets/alice/bans
```

```json
{
  "total": 2,
  "tracking": true,
  "bans": [
    {"address": "2001:db8:1:2::/64", "expires_at": "2026-10-07T16:42:10Z"},
    {"address": "203.0.113.44", "expires_at": "2026-10-07T16:42:10Z"}
  ]
}
```

Lift one, by the /64 the listing shows or by any address inside it:

```bash
curl -s -X DELETE -H "Authorization: Bearer a-long-random-string" http://127.0.0.1:9090/secrets/alice/bans/2001:db8:1:2::/64
```

```json
{"removed": 1}
```

What a ban request takes:

- `ips`: 1 to 4,096 entries. Each is a literal IP address with no zone, or an
  IPv6 /64 in prefix form, the way `/clients` and `GET /bans` spell it. Any other
  prefix is `400`.
- `ttl`: a Go duration in `(0, 720h]`; absent is `1h`. Days are not a unit:
  `"30d"` is `400`, write `"720h"`.
- `force`: needed to ban an address that does not stand for one place —
  loopback, private, link-local, unspecified, multicast — or the one IPv6 /64
  that holds some (`::/64`). Without it such a request is `400` and says so.
  Behind a carrier on loopback that sends no PROXY header every client is
  `127.0.0.1`, so banning it with `force` bans every client from the secret.

What a ban does:

- **It is held per place and per secret.** A place is an IPv4 address (a
  v4-mapped address is its IPv4 address) or an IPv6 /64, as for `kick`, so
  banning `2001:db8:1:2::5` bans the whole `2001:db8:1:2::/64`. Alice's ban does
  not touch bob.
- **It ends the place's live streams of that secret**, and it is recorded and
  the streams are found in one step, under the lock admission uses, so no stream
  gets in between the ban and the close. It also forgets that secret's handshake
  hint for the place.
- **At the doors a banned place is turned away as a wrong secret is.** On
  FakeTLS it is fronted to the cover site before the server answers, and the
  cover site receives exactly what it would for a wrong secret. On an obfuscated
  `[[listener]]` it takes the same exit as every other refusal there, and on a
  `public = true` listener the attempt is charged to that address's
  `handshakes-per-ip` budget like a frame that matched nothing. A ban recorded in
  the moment between a stream's secret matching and the stream registering is
  caught by a second check, which closes the stream after the handshake; that
  late refusal is not charged to the budget.
- **Banning a place that is already banned sets a new expiry**, shorter or
  longer: the latest request wins. It takes no new slot.
- **At most 4,096 bans are held across every secret.** A request that would go
  past that is refused whole with `409` `ban list full`. Lapsed bans hold no
  slot.
- **`banned` counts the distinct places in the request**, already-banned ones
  included; `closed` counts the streams closed. `addresses`, the places in the
  unit they are held at, is echoed only with `track-client-ips`, so with tracking
  off nothing in the answer shows that an IPv6 address was banned as its /64.
- **It lives in memory only.** It survives `POST /reload` and a re-key of the
  secret. It goes when the secret is removed, and with the process on restart.
- **It is not counted on its own.** No `/stats` field, event or metric of its
  own counts banned attempts; on an obfuscated listener they are inside
  `obfuscated.denied` with every other refusal. The API logs
  `addresses banned through the API` with the secret name and the two counts and
  no address. A refused attempt logs `connection denied by per-user limit` with
  `deny_reason` `banned`, carrying the stream's `client-ip` as every stream line
  does. Both are at info level, which only `debug = true` shows.

`GET /bans` is gated as `external_ips` is: `total` is always there, and `bans`
— each with `address` and `expires_at`, UTC, sorted by address — only with
`track-client-ips`. `DELETE` takes the address as a literal IP or as the /64
form, needs no `force`, and is idempotent. A malformed request is `400` even for
an unknown secret; a well-formed one for an unknown secret is `404`.

### Kick, ban or re-key

| | What it does | How long | Use it for |
|---|---|---|---|
| `kick` | Closes the streams one place holds on one secret. The device reconnects at once. | A moment | A device that is one too many, when `ip-limit` should decide whether it comes back |
| ban | Closes them and refuses the place that secret until the ban lapses | Up to `720h`, in memory; lost on restart | Short-term abuse from one place |
| re-key | Gives the secret a new key (`POST /secrets` with a new `secret`, or the file and a reload). Every live connection of the secret closes and every holder needs a new link | Permanent | A leaked link that must stop now |
| rotate | Gives the secret a new key and keeps the old one accepted until a time you choose (`mtg-proxy rotate-secret`, then a reload). Nothing closes at the rotation; at `until` the old key is refused and its live connections close | Permanent; the old key for the overlap only | A leaked link whose rightful holders need time to move |

A ban is a refusal, not concealment. Someone who holds the secret and connects
from a banned place can tell from the timing that the key matched, and can come
back from another place. For a leaked link, re-key the secret, or rotate it with
an overlap so that its holders can move to the new link without a gap (below).
See [[Security]] for what a ban does and does not hide.

### What a mutation does to live connections

`POST`, `PUT` and `DELETE` all go through the same atomic swap as a file reload:

- a **new** secret starts working immediately;
- a **re-keyed or removed** secret has its live connections closed, because the
  key they were admitted with no longer exists;
- more exactly, each live connection is judged by the key it came in on (feature
  `secret-rotation`): it is closed when the new set no longer accepts that key
  for its secret, and left alone when the set still does, as the primary or as
  an unexpired previous key. So a rotation closes nothing, and the end of its
  overlap closes the old key's connections and only those;
- an **ad-tag-only** change leaves connections running — the tag affects the
  routing of new connections only;
- **disabling** a secret, or giving it an expiry already in the past, closes its
  live connections immediately;
- a **quota** lowered to or below what the user has already used closes their
  live connections too, and a quota reached mid-stream ends the stream at the
  byte that reaches it (v1.8.0; before, a quota was checked only at admission);
- a changed **per-address limit** reaches open connections without closing any:
  a lowered `client_conns` binds the next connection, and a ceiling or a fair
  share is re-rated in place;
- **bans** carry over, a re-keyed secret's included; a removed secret's bans go
  with it;
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
the roster should write the file first and then call `/reload`. Bans are the
exception: the file has no place for them, so a reload leaves them alone. They
end when they lapse, when they are lifted, when their secret is removed, or when
the process restarts.

Overlaps are the other way round: the file is their only source. No route can
write a previous key. A route that rotated a key in memory would be undone by
the next reload or restart, which reads the file and makes the leaked key the
primary again while the new link handed out dies; the proxy never writes its
config file, and in a panel deployment the panel owns it. So an overlap is
written to the file by `rotate-secret` and read by a reload, and the routes
only keep what the file granted — see
[what the API does to an overlap](#what-the-api-does-to-an-overlap).

One practical consequence: `mtg-proxy access` reads the config file, not the
API. A user added only through `POST /secrets` gets no link from `access` until
they are also in the file.

## Rotating a secret with an overlap

New with the `secret-rotation` feature. A re-key cuts every holder of a link at
once. A rotation gives the secret a new key and keeps the old one accepted until
an instant you choose, so the people who rightfully hold the link can move to
the new one without a gap; then the old key is refused, and its live
connections are closed.

**An overlap is a grant.** Until `until`, whoever holds the old link — the
person it leaked to included — uses the secret exactly as its rightful holders
do: the same quota, speed, address limit and connection caps. A link posted in
public can crowd them out of `ip-limit` and `client-conns` for as long as the
overlap lasts. Choose a short one, or `--overlap 0` with bans of the abusive
places, for a hostile leak; see *Rotating a leaked link* on [[Security]].

### The command

The overlap lives in the config file, as a `[[retiring-secret]]` block (see
[[Configuration]]), and `mtg-proxy rotate-secret` writes it. It makes no
network access unless you give `--reload`.

```bash
mtg-proxy rotate-secret /etc/mtg-proxy/config.toml alice --overlap 24h
```

On stderr, for people:

```text
rotated "alice" in /etc/mtg-proxy/config.toml
the previous key is accepted until 2026-10-13T09:30:00Z (24h0m0s from now)
the running proxy does not know yet: POST /reload on its management API, or restart it
links: mtg-proxy access /etc/mtg-proxy/config.toml
```

On stdout, exactly one line: the new value, spelled as the old one was (hex if
the file had hex, base64url otherwise). It is printed once, right after the
file is replaced and before any reload, so redirect it if a script needs it.
With `[web] enabled = true` stderr also says `WEB links of "alice" change now;
the WEB transport has no overlap (see WEB-Proxy-Setup)`.

What the edit does to the file:

- **The new key** goes into alice's line in `[secrets]` (or the top-level
  `secret` for `default`), in the same form (`ee`, `dd` or plain) and, for `ee`,
  with the same fronting host unless `--host` names another. A mode change is a
  hand edit; [[Configuration]] shows one.
- **The old value** goes into a new block just above the `[secrets]` header,
  with `until` in UTC to the second and a `# added by mtg-proxy rotate-secret at
  <time>` comment inside it. A file with no `[secrets]` header gets it at the
  end.
- **Nothing else changes.** The file is edited in place as text, never
  rewritten from scratch: comments, order, quoting and line endings stay. The
  result is parsed again and must differ from the original in exactly the
  intended places, or nothing is written.
- **It never writes a block the proxy would drop**, or one that would make a
  dead key usable again, and it never writes an overlap over 720h.

Then reload the proxy (or pass `--reload`), and hand every rightful holder the
new link, from `mtg-proxy access`, before `until`. Their clients keep working on
the old link until then; after it, only the new link works. The reload is
`POST /reload` or a restart: `run` has no `SIGHUP` handler, and a `SIGHUP` ends
it, as it always has.

| form | does |
|---|---|
| `rotate-secret <config> <name> --overlap <d>` | Rotates `<name>`. `<d>` is a Go duration from `0` to `720h` and has no default: a security action states its grant. `0` writes no block and is an immediate re-key: the old key dies at the reload. Below `1s` (other than `0`) is refused. `--host` gives an `ee` secret a new fronting host. |
| `rotate-secret <config> <name> --end-overlap` | Removes every block of `<name>`, expired or not: its old keys stop at the reload. |
| `rotate-secret <config> --prune` | Removes every block whose `until` has passed, of any name. It also combines with either form above. |
| `--dry-run` | Says on stderr what the run would do, and writes nothing. No key is generated, and no diff is printed: it would show the old value. |
| `--reload` | Reloads the running proxy through its management API and reads the rotation back (below). |
| `--force` | Goes past the two refusals that are guesses: the panel file name, and a running proxy without `secret-rotation`. Never past a validation failure. |

`default` names the single top-level `secret`, and only while the file has no
`[secrets]`. A secret holds at most 4 unexpired previous keys: a fifth rotation
is refused until one expires, or `--end-overlap` ends them.

### What happens over time

| moment | the new key | the old key |
|---|---|---|
| the file is written | not served yet: the running proxy has its old set | as before |
| the reload (or a restart) | the primary, at once | accepted until `until`; no live connection is closed |
| during the overlap | works | works, as the same user |
| `until` | works | refused at the door, as a wrong key is; its live connections close at the next five-second sweep, or at any reload or API change before it |
| a restart during the overlap | the file's | accepted until `until`: the file still says so |
| `--end-overlap` and a reload | works | refused, and its connections closed, at that reload |
| a binary without `secret-rotation` reads the file | the file's | refused: an older binary ignores the table as an unknown key (one recent enough to name unknown keys logs it), and an older `run --check` refuses the file |

Expiry is exact for new connections; only the live ones wait for the sweep. A
connection that matched a key in the moment before a reload or the expiry took
that key away, and registers after it, is refused there and logged as
`connection denied by per-user limit` with `deny_reason` `key_revoked`.

To cut the old link **now** rather than at `until`: `rotate-secret <config>
<name> --end-overlap` and a reload, which ends every old key of that name. A
kick of the abusive places closes their streams on both keys, and a ban refuses
them on both, because a ban is held per secret and place, not per key — but a
ban lives in memory only and goes with a restart.

The proxy's log says what each swap did, by name and never by key: see *Logs*
on [[Monitoring]].

### `--reload` and the read-back

`--reload` reads `api-bind-to` and `api-token` from the same file; a wildcard
bind (`0.0.0.0`, `::`) is reached on the loopback of its family. Without
`api-bind-to` it is refused before anything is written. In order:

1. **Before writing:** `GET /stats`. An API that does not answer is a refusal.
   So is a proxy whose `features` lack `secret-rotation`: an older binary
   ignores the block, and its reload would end the overlap at once. `--force`
   goes past that one with a warning.
2. **The write.**
3. **`POST /reload`**, which must answer `200`.
4. **The read-back.** For the name, `GET /secrets/{name}`, compared with what
   the written file says the proxy must serve: the same primary (key, form and
   host), `retiring_keys` equal to the name's usable blocks, and, after a
   rotation, `retiring_until` no earlier than the new block's `until`. A name
   whose expired blocks `--prune` removed gets the count check.

When it all holds the run says `reloaded the proxy through its management API at
127.0.0.1:9090; it serves the file as written`. A check that fails is a line of
its own, with its likely causes:

```text
the file is rotated but the proxy does not serve it: retiring_keys of "alice" differs (1 vs 0); likely: the proxy's clock is ahead of this machine's (its latest time judged an entry expired), or the proxy logged a problem with a [[retiring-secret]] block
```

- **A different primary** points at a `SECRET` environment variable overriding
  `[secrets]`, a single-file bind mount that still shows the old file, or
  another process that rewrote the file.
- **More previous keys than the file says** point at a proxy reading another
  file, or this machine's clock being ahead of the proxy's.
- **After `--force` past an older binary**, a shortfall names `the running
  proxy is an older binary (--force), which ignores [[retiring-secret]]` first,
  and a proxy that does not serve `GET /secrets/{name}` is named as such. Expect
  a non-zero exit there after a rotation with an overlap: the older binary holds
  no previous key.
- **A refused reload** prints its status line only, never the body, which is the
  proxy's own error text: the proxy's log says why.

The file is **never rolled back**. It is the truth, and a rollback would make
the leaked key the primary again at the next restart. `--reload` reaches one
proxy: reload every other process that reads the file yourself (the WEB relay
follows the file by itself). `--dry-run --reload` asks the pre-check and writes
nothing.

### Exit status and refusals

`0` is success, a run with nothing to do included (`nothing to do: … nothing was
written`). Anything else exits non-zero, and every message says whether the
file was written: a refusal, and any failure before the file is replaced, ends
in `nothing was written`; a failure after it — the reload, the read-back — says
the file is rotated (or written) and what did not happen. Refusals worth
knowing:

- `say how long the previous key stays accepted: --overlap 24h, or --overlap 0
  to retire it at once`;
- `"default" is not served while [secrets] is present; rotate a name from
  [secrets]`;
- `<name> already has 4 unexpired previous keys, the most one secret can have:
  end them with --end-overlap, or wait for one to expire, and retry`;
- the current key still held by another block until a later time, which names
  that block and how to end it; another name's block, or another name's
  primary, already holding the key being retired; a removal that would make a
  dead key usable again. Each names the block, never a key;
- `the edit would add a problem the file does not have: …`, with the line
  `run` would log;
- a config that does not load, with the parser's error (the shapes on
  [[Configuration]] that refuse the whole file, a byte-order mark);
- `the file changed while rotating; nothing was written`: another writer (an
  editor, the panel) changed the file between the read and the replace;
- `this looks like a config the Penhoon panel generates (…/mtproto/mtg-N.toml);
  the panel rewrites it from its own records and would make the old key the
  primary again; re-key the client in the panel instead`.

**Not for a panel-managed file.** The panel rewrites its config from its own
records and would make the old key the primary again. The refusal above is a
guess from the path (`…/mtproto/mtg-<digits>.toml`), so `--force` passes it,
and a panel that keeps its files elsewhere is not recognised at all: rotation is
unsupported on any file a panel writes. Re-key the client in the panel.

### How the file is written, and what can be left behind

The only write is atomic: a temporary file `<config>.rotate-<8 random hex>.tmp`
beside the config, given the config's permissions before anything is written
into it, then written, synced and renamed over it. No copy of the old file is
ever made — it would be a second file holding every secret with the leaked key
as the primary. A symlinked config has its target replaced; the link stays.

- **The lock.** `<config>.rotate.lock`, holding the pid and the start time,
  keeps two runs apart, a dry run included. A lock that exists is refused with
  its age: `another rotate-secret holds <lock> (started <age> ago); if none is
  running, remove it and retry`. The tool never breaks a lock itself. It is
  created exclusively, which is reliable on local file systems only: **a config
  on NFS is not protected against two concurrent runs.**
- **After a crash** — the process killed, the machine down — the lock can stay,
  and before the rename the temporary file can too. The temporary file holds
  every secret of the config: delete it. The lock refusal names any such file
  it finds beside the config.
- **Interrupts.** The first Ctrl-C, `SIGTERM` or `SIGHUP` does not kill the
  run: before the rename it stops cleanly there, and removes the temporary file
  and the lock (`interrupted; nothing was written`); after the rename the
  rotation is complete, so the run exits `0` with `warning: interrupted after
  the file was written; the rotation is complete`, and with `--reload` it says
  the reload was not finished or not read back. A **second** interrupt kills
  the process as usual and leaves the lock behind (and, before the rename, the
  temporary file). A signal ignored at the start (`nohup`) stays ignored.
- **Another writer.** The file is read again just before the rename, and a
  change since the run read it aborts it. A short window between that read and
  the rename remains.

On Unix the temporary file is created `0600`, then given the config's owner,
group and permission bits exactly, whatever the umask; a run that cannot set
the owner is refused (`run as the file's owner, in the file's group, or as
root`). The directory is synced after the rename. A config with other hard
links is warned about, here and on Windows: `the config has N names (hard
links); the others keep the previous file: replace them by hand` — those names
still hold the old key as the primary. A read-only mount is refused with `(a
read-only mount? run rotate-secret on the host, and mount the config's
directory into the container)`; a single-file bind mount, with `cannot replace
<config>: it is a mount point (a single-file bind mount?); run rotate-secret on
the host, and mount the config's directory into the container`. See [[Installation]] for
Docker.

On Windows the new file is created readable by the runner alone and shared with
no one until the config's security is copied onto it:

- **Kept:** the access control list exactly as it was — its entries, the
  inherited ones as they were, protected or not, and a NULL list (open to
  everyone) — and the mandatory integrity label, or its absence.
- **Not kept:** the owner (the new file's owner is the runner; for an elevated
  runner, Administrators), alternate data streams, audit entries, and the
  hidden and system attributes. A read-only config is refused like any config
  the runner cannot open for writing.
- **EFS.** A config encrypted with EFS is refused: `rotate-secret cannot keep a
  file encrypted with EFS; decrypt it with cipher /d "<config>", rotate, and
  encrypt it again with cipher /e "<config>"`. A plain config in a directory
  that encrypts new files comes back encrypted under the runner's key.
- **A rotated config always carries a label part**, `S:NO_ACCESS_CONTROL` when
  it had no label: the same access and the same `icacls` output, but a tool
  that compares raw SDDL sees a difference.
- **When the copy comes out different**, the run refuses with nothing written:
  `the new file would not get the access control list of <config>: the copy
  differs from the original; give the file a list of its own with icacls
  "<config>" /inheritance:d, and retry`. For a label, the remedy never suggests
  a tool that would weaken it.
- **Not tried** on SMB shares, ReFS or FAT. A volume with no security (FAT) has
  nothing to copy; one that rejects the descriptor or the label makes the run
  refuse, with nothing written.

### What the API does to an overlap

The routes cannot create or extend an overlap: the bodies have no field for
it. They keep what the file granted, a removal takes a secret's previous keys
with it, and the next `POST /reload` or restart returns to the file.

| call | the secret's previous keys afterwards |
|---|---|
| `POST /reload` | exactly the file's usable blocks |
| `PUT /secrets` | the current ones of every name the body keeps, whatever else the body changes; a name the body drops loses them. A panel's re-key stays immediate: the old primary never becomes a previous key |
| `POST /secrets` | the name's are kept; the old primary never becomes one |
| `DELETE /secrets/{name}` | the name's go with it |
| `PUT`/`DELETE /adtag` | kept |

**Reverting puts the leaked key back on purpose.** A `POST` or `PUT /secrets`
that makes a secret's previous key its primary again — the key you just retired
— does exactly that: the block's key is now the primary, the new key's
connections close, and the proxy logs `previous key of the secret is the primary
again` at warning level, with `secret_name` and `closed` (after `a retiring key
was ignored` with `reason` `same_as_primary`, at info). A `POST` or `PUT` that
gives the previous key to **another** secret makes it that secret's primary: the
first secret stops accepting it and its connections on it close, logged as `a
retiring key was ignored` with `reason` `key_of_other_secret` at warning level,
then `previous key of the secret is no longer accepted` with `reason` `removed`
and `closed`. Either lasts until the next reload, which returns to the file.

### The four fields

On `GET /stats`, inside the user's own object, and on `GET /secrets` and
`GET /secrets/{name}`; never a key under `users`, never a key's value, and
absent for a secret with no unexpired previous key:

| field | means |
|---|---|
| `retiring_keys` | How many previous keys the secret still accepts. |
| `retiring_until` | The latest `until` among them, in UTC: when the last old link stops. |
| `retiring_connections` | Live connections of the secret on a key that is not its current primary: the old-link users still connected. Counted when you ask, from each connection's own key, so right after a rotation it shows every old-link connection, and it falls as they move. Absent at `0`. |
| `retiring_last_seen` | When a connection last came in on a previous key, in UTC. Cleared when the secret starts an overlap after having none, so it never shows an earlier overlap's traffic. |

`retiring_connections` at zero and an old `retiring_last_seen` say the old link
is no longer used; `--end-overlap` ends it early. A user on the old link is
counted in the user's other fields as any connection is.

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
| `400` | Malformed JSON, an unknown JSON field, an invalid secret, a bad ad-tag, an unparseable quota, speed or expiry, a kick naming no valid address, or a swap that would leave nothing to front. Also: a negative `client_conns`; a `client_speed` that is zero, under `64kbit` or not a rate; `client_fair` without `speed`, `speed_up` or `speed_down` beside it; a `/clients` `limit` that is not a whole number above zero; a ban naming no place, more than 4,096 places, something that is not an IP address or an IPv6 /64, or an address that does not stand for one place without `force`; a ban `ttl` outside `(0, 720h]`; an unban address that is not an IP address or an IPv6 /64. These are answered before a `404`. |
| `401` | `api-token` is set and the `Authorization` header is missing or wrong. |
| `404` | Unknown secret name on `GET` or `DELETE /secrets/{name}`, `/reset-quota`, `/kick`, `/external-ips`, `/clients` or `/bans`; unknown path. |
| `405` | Wrong method — `POST /stats`, or anything but `POST` on `/reload`. |
| `409` | `DELETE /secrets/{name}` would remove the last secret, or a ban would take the ban list past 4,096 (`ban list full`). |
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
- `[[retiring-secret]]` (feature `secret-rotation`)

**Not hot-applied.** Everything else needs a restart: `bind-to`, `api-bind-to`,
`api-token`, `[[listener]]` blocks, `[domain-fronting]`, `[network]`,
`[throttle]`, `track-client-ips`, `usage-state-file` and the whole `[web]`
table. A reload does not report these as unchanged or refused — it reads the
whole file, validates it, and applies only the items above. If you edited
`bind-to` and called `/reload`, the call succeeds and the port does not move.

The reload path runs the same parse, environment overlay and validation as
startup, which has two consequences. An invalid file is a `500` and the current
set keeps serving — a proxy that emptied its roster because someone saved a
broken file is far worse than a stale one. And environment overrides are
re-applied on every read, so a `SECRET` or `TAG` pinned in the environment
survives a reload rather than being replaced by whatever the file says. See
[[Configuration]].

A mistake inside a `[[retiring-secret]]` block is not an invalid file: the
block is dropped with a warning and everything else is applied, the new primary
included, so the worst it does is end that old link early. Only a shape of the
table that does not parse refuses the reload, and then the `500` says the set in
force is kept. See `[[retiring-secret]]` on [[Configuration]].

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
