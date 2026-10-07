# Per-address governance inside one shared secret — design

Date: 2026-10-07. Status: approved under delegation ("go all completely by yourself"); to be
independently reviewed before any code (see the end). Piece B of the shared-secret program
(A handshake at scale — done; **B this piece**; R rotation with an overlap period; C bounded
slow-reader queue; D per-address web-profile shaping). B and R are separate pieces on purpose:
B changes the data path, admission and the stats API; R changes both handshake doors, the
config tables, stream closing and the WEB relay.

## The goal, as stated

One secret shared by many people already works on the wire. But the speed limit, the quota, the
ip-limit and the `/stats` counters are all per secret, so one heavy user drains everyone's
share and nobody can see who is using what. Give a shared secret per-**source-address**
controls: a speed share, a connection cap, per-address usage in the stats, and a way to kick
and ban an abusive address.

(Retiring a leaked link — rotation with an overlap — is piece R.)

## Who is an "address"

An address is what the existing per-address features count: an IPv4 address, or an IPv6 /64
(`keyOfAddr`, `address_limit.go`). Two consequences this piece states instead of hiding:

- **Carrier-grade NAT shares an address among many people.** A per-address share is a share
  per *address*; a mobile carrier's NAT address with 200 users gets one share. Every
  per-address control is therefore optional and off by default.
- **Automatic controls apply only to addresses that stand for one place.** The per-address
  speed cap, fair share and connection cap use the same classification as the hint cache
  (`hintKey`): loopback, private, link-local, unspecified and multicast addresses are
  *unkeyed*, get no per-address entry and are governed at the secret level only. Behind a
  loopback carrier that forwards no client address (the WEB relay backend without a PROXY
  header), every client would otherwise be one "address" and a cap would throttle everyone at
  once. Operator-explicit actions (kick, ban) act on exactly the address the operator names,
  as `kick` does today. Clients on a private network that reach the proxy directly are
  therefore not distinguished by the automatic controls.

## Where things stand

- Speed (`speed`, `speed-up`, `speed-down`) and quota are per secret; a user's connections
  share one token bucket per direction (`speedLimiter` in `speed_limit.go`, enforced in
  `countingConn`).
- `ip-limit` caps how many distinct addresses a secret may use at once; nothing caps how many
  connections or how much bandwidth one address may take.
- Per-address state today is a refcount in `addressLedger`, dropped when the address's last
  connection closes, so nothing about an address (bytes, a bucket, a ban) can live there.
- `kick` closes an address's live streams and nothing more: the device reconnects at once.
- `connected_ips` lists addresses but carries no bytes, no throttle time, no cap.
- The config file is the panel's; the panel regenerates it wholesale and never writes any key
  of this piece (see "Contracts").

## Decisions

1. **One bounded per-address table**, keyed by (secret name, address), with its own lifetime:
   it survives reconnects (so a bucket does not reset on every new connection) and is dropped
   after the address has been idle ten minutes with no live connection.
2. **State exists only where it is needed.** A table entry is created only if the proxy
   keeps client addresses (`track-client-ips`) or the secret has a per-address control
   (`client-conns`, `client-speed`, `client-fair`). Otherwise the data path is exactly what
   it is today: a nil pointer and no extra work.
3. **Drop-new when full, never evict.** The table is capped at 32,768 entries across all
   secrets. A new address when full gets no entry (it is governed at the secret level) and is
   counted; an existing entry is never pushed out (pushing out would hand a drained bucket
   back full — the lesson of piece A).
4. **A real fair share, not just a cap.** `client-fair` divides a secret's speed limit among
   its *active* addresses by max-min fairness, work-conserving: an address that uses less than
   its share leaves the rest to the others. A static per-address ceiling (`client-speed`) is
   separate and combines with it.
5. **One per-address bucket with a rate hook.** The per-address limiters are re-rated only
   through one function; the fair-share ticker is its first caller and piece D's adaptive
   rate plugs into the same hook. The dynamic limiter is built once.
6. **Kick and ban are operator actions on `addressKey`**, memory-only, with a TTL; the ban is
   checked at attribution, so a banned address is turned away exactly like a wrong secret.
7. **Nothing per-address appears as a key under `users`** in `/stats` (the panel bills every
   `users` key as a client); the address list is its own endpoint.

## 1. The table

`mtglib/client_table.go`. One `clientTable` on `Proxy`, guarded by `liveMu` for map access (as
the address ledger is); entries are read on the data path through atomics only.

```
type clientEntry struct {
    key                     addressKey
    name                    string          // the secret
    conns                   int32           // live connections (maintained under liveMu)
    bytesIn, bytesOut       atomic.Int64
    firstSeen               time.Time
    lastSeen                atomic.Int64    // unix nanos of the last byte or connection event
    speed, speedUp, speedDown speedLimiter  // nil-limit until a cap applies
    // fair-share bookkeeping (touched only by the ticker under rateMu)
    ...
}
```

- **Created** in `tryRegisterConn` (under `liveMu`, after the secret-level admission checks) when
  the address is keyed and the secret needs an entry (decision 2); the pointer is stored on the
  stream context next to `addrKey`. `conns` is incremented there and decremented in
  `unregisterConn`.
- **Dropped** by a sweep every 60 s (the maintenance loop): `conns == 0` and idle for ten
  minutes. A burst of new addresses past the cap is counted in `clients_overflow`.
- **Retention, stated exactly:** an entry holds an address and the secret name it used, byte
  counts, two times and limiter state, in process memory, from the first connection until ten
  minutes after the last one closes; never logged, never persisted. It exists only where
  decision 2 says. (This is the association the hint cache also holds; it follows the same
  `track-client-ips` rule for being *listed*.)
- Tests build `Proxy{}` literals: every new field is nil-safe and means "off".

## 2. The connection cap

`client-conns` (int ≥ 0, 0 = unlimited) in `[secret-limits.<name>]`, `client_conns` on the API.
Checked in `tryRegisterConn` beside the ip-limit check, under `liveMu`: a new connection from a
keyed address whose entry already holds `client-conns` live connections is refused — closed
after the handshake, exactly as an ip-limit refusal is (`DenyClientConns`), counted per secret
(`client_conns_refused`), no new event type. Lowering the cap never drops streams. Distinct from
`ip-limit` (how many *addresses*): a Telegram client opens several connections, so the cap
should be set to a few times that.

## 3. Speed: a static ceiling and a fair share

`countingConn` gains a nil-safe per-address step. For a stream with an entry:

- **Cut** each read/write by the entry's limiters' burst (a nil limiter does not cut: an
  unlimited user still writes once — `TestUnlimitedUserWritesOnce`).
- **Wait on the per-address bucket first, then the secret-level ones.** `WaitN` reserves tokens
  before sleeping, so waiting on the shared bucket first would let a capped device drain
  tokens its siblings need. Reads stay post-paid, writes pre-paid, as today.
- **Count** bytes in/out on the entry (the only two places bytes are counted).
- A wait on a per-address bucket also adds to the *user's* `throttled_ms` (a throttled user is
  a throttled user) and to the entry's own throttled time.

**Static ceiling.** `client-speed` (bytes/s, `ParseSpeed` rules, floor 8,000) is one combined
bucket per address, like `speed`. Setting or lowering it re-rates live entries (through
`applyLimits`, as the secret-level speed is); removing it sets the limiter to unlimited.

**Fair share (`client-fair = true`).** The secret's configured `speed`, `speed-up` and
`speed-down` are each divided among the secret's active addresses:

- *Active* = an entry with at least one live connection that moved a byte in the last 10 s.
- Every second a ticker (under the proxy context) takes a snapshot of the active entries of
  each fair secret and computes, per configured direction, a max-min fair allocation from each
  address's measured demand:

  ```
  fairShares(total, demands) -> allocations     // pure, no clocks
    sort ascending by demand; remaining = total
    for i: share = remaining / (n - i); a[i] = min(demand[i], share); remaining -= a[i]
  ```

  where an address that was *not* throttled in the last second has demand
  `max(1.5 × its observed rate, total / (2n))` (growth headroom, and a floor so a quiet
  address can start at half its fair share at once) and one that *was* throttled has demand
  = +∞. Properties, all tested: the allocations sum to at most `total`; none is below
  `min(demand, total/n)` (the guarantee); no address is given less while another is given
  more than it can use (max-min).
- Each address's limiter rate is `min(static ceiling if any, allocation)`. A new address
  starts at `total / (n + 1)` immediately and the others shrink at the next tick (worst case
  one second of the old split). The secret-level bucket still enforces the total.
- Rates are changed only through `(*clientTable).setRate(entry, direction, bytesPerSecond)`
  (the hook D uses), serialised by one mutex shared with `applyLimits`, because
  `speedLimiter.set` is safe against concurrent waits but not against a concurrent `set`.

## 4. Stats

- **Per-user scalars** (omitempty, inside the existing user object — never new `users` keys):
  `clients` (entries held), `clients_overflow`, `client_conns_refused`.
- **A new endpoint** `GET /secrets/{name}/clients?limit=N` (default 100, max 1,000), listing
  entries by bytes descending with `total` and `overflow`: `address` (the address key: an
  IPv4 address or an IPv6 /64 prefix), `connections`, `bytes_in`, `bytes_out`, `throttled_ms`,
  `first_seen`, `last_seen`, `speed_limit` (the address's current limiter rate, 0 = none),
  `banned_until`. **Gated exactly like `connected_ips`**: addresses are listed only when
  `track-client-ips` is on; otherwise the endpoint answers 200 with the counts only and
  `"tracking": false`. 404 for an unknown secret; behind the bearer token like every route.
- `throttled_ms` keeps meaning "time this user's connections spent held to a limiter" and now
  includes per-address waits.
- Feature strings: `client-limits` (the three keys/fields), `client-stats` (the endpoint and
  scalars), `client-bans` (section 5). Inserted in sorted position; the hard-coded lists in
  `proxy_stats_features_test.go` and the every-route subtest are edited deliberately.

## 5. Kick and ban

`kick` is unchanged. New, behind the bearer token, memory-only:

- `POST /secrets/{name}/bans` `{"ips":["203.0.113.9", ...], "ttl":"1h"}` → bans the named
  addresses (as `addressKey`, exactly like `kick`: an IPv6 address bans its /64) for `ttl`
  (default 1 h, max 30 d) **and closes their live streams in the same `liveMu` critical
  section** (so no stream registers between the ban and the kick). Response
  `{"banned":N,"closed":M}`. 409 `ban list full` past 4,096 bans across all secrets (a ban is
  an operator action: refuse it loudly rather than evict another).
- `GET /secrets/{name}/bans` lists `{"address","expires_at"}`; `DELETE /secrets/{name}/bans/{ip}`
  lifts one.
- **Enforcement** in `attribute()` right after `checkLimits`, and re-checked inside
  `tryRegisterConn` under `liveMu` (the race window): a banned address is refused like a
  wrong secret — fronted on FakeTLS, `denyObfuscated` on the obfuscated door (`DenyBanned`).
  Because it happens after the secret matched, the budget charge is kept and no hint is
  written (A's rules, unchanged).
- **A ban lives in memory only** and survives a reload (a reload rebuilds the secret set, not
  the proxy), but not a restart. Rotation (piece R) is what actually retires a leaked link; a
  ban is the short-term tool for an abusive address. The docs say so.

## 6. Config, API and contracts

- **Config** (`[secret-limits.<name>]`): `client-conns` (int), `client-speed` (string like
  `speed`), `client-fair` (bool). Parsed and validated like their neighbours (`TypeSpeed`;
  a new `TypeClientConns` — not `TypeIPLimit`, whose messages name "ip-limit"). `UnknownKeys`
  must stay empty for the panel's emitted file; an older binary logs the new keys as unknown
  on `run` and refuses them only under `run --check`.
- **API** (`PUT`/`POST /secrets`, read back by `/secrets`, `/stats`, `GET /secrets/{name}`):
  `client_conns`, `client_speed`, `client_fair` in `limitFields`, `SecretLimits.IsZero`,
  `fillLimitInfo` and the `handleStats` overlay. A `POST /secrets` clears any limit field not
  sent — every new field is therefore added to all of them. The fork's API is strict
  (`DisallowUnknownFields`), so a client must gate on the `client-limits` feature.
- **Panel contract:** nothing under `users` keys; no existing field, route, key or feature
  changes; default `accept-modes` unchanged. **The panel can neither write nor preserve these
  keys**: it regenerates the config file wholesale and its `PUT`/`POST /secrets` bodies carry
  none of them, so a panel-managed inbound cannot use this piece until the panel adopts the
  fields. This piece therefore targets hand-managed configs (the live server) and the API
  fields for future panel adoption. API-set limits vanish on the next `POST /reload` (they
  always have); bans do not.
- **Usage state file untouched**: it is keyed by secret name and any extra top-level key
  would become a phantom billed user.
- **No wire change**: not one byte the proxy sends changes; golden tests untouched.

## 7. Proof

**Test seams.** The fair-share ticker takes a clock and an explicit `tick()`; `fairShares` is
pure; address-dependent tests use address-controlled connections (`dialProxyFrom`,
`remoteAddrConn`) with documentation-range addresses (keyed); loopback peers are unkeyed.

**Correctness (test first, each sabotage-checked)**

- *fairShares* against a brute-force max-min reference on 10,000 seeded random inputs;
  properties (sum ≤ total; guarantee; never raising an address above its demand while
  another is below its share; permutation-invariance); extremes (one address, zero demand,
  total smaller than n × floor).
- *Table*: created only where decision 2 says; refcounts through connect/disconnect;
  idle sweep keeps live and recently idle entries; the 32,768 cap drops new addresses and
  never evicts or resets an existing entry; unkeyed peers get no entry; IPv4-mapped and
  same-/64 peers share one; nil-safe on `Proxy{}`.
- *Connection cap* end to end through the real door: the (cap+1)th connection from an
  address is refused after the handshake, a different address is unaffected, a release
  frees a slot, lowering the cap never drops streams, `client_conns_refused` counts, a
  loopback (unkeyed) peer is never capped.
- *Static ceiling* against the clock on both doors and both directions (the style of
  `TestSpeedLimitAppliesThroughTheProxy`): two addresses of one secret with the cap hold
  each to the cap; an unkeyed peer is not capped; an unlimited secret still writes once.
- *Fair share* end to end: two active addresses split a secret's `speed-down` about equally
  (within a stated tolerance, over a window); one address idle ⇒ the other gets nearly all
  of it (work-conserving); a third arriving gets its share within two ticks; the sum never
  exceeds the secret's limit.
- *Kick/ban*: a ban refuses at attribution with the same bytes to the cover site as a wrong
  secret; ban + kick is atomic (a hammering connector cannot slip a stream in); TTL expiry
  with a fake clock; unban; the 4,096 cap returns 409; survives a reload.
- *Stats*: nothing new under `users` keys; scalars omitted when zero; `/clients` gated like
  `connected_ips`; ordering and `limit`; `throttled_ms` includes per-address waits; shape-
  pinning tests untouched and green.
- *Config/API*: keys known (no `UnknownKeys`), `Config.String()` unchanged for configs not
  using them, the panel-contract test untouched and green, `POST /secrets` neither clears nor
  drops them when sent and clears them when not, features sorted.

**Sabotage checks** (each new test fails when its behaviour is removed): drop the
per-address wait; wait on the secret-level bucket first; evict on full; reset a bucket on
reconnect; key unkeyed peers; skip the ban re-check under `liveMu`; ban without kick; kick
without ban; let `fairShares` exceed the total; let a throttled address's demand be finite;
list addresses without `track-client-ips`.

**Benchmarks (box, same-session A/B; baseline first)**: `countingConn` bulk throughput per
door (ee/dd/plain, 1 and 16 connections) with no per-address entry — must not regress by more
than noise (the nil-pointer path); with a static ceiling set above the link speed (the cost
of the extra bucket); with fair share on 16 addresses (the ticker's cost). The existing
`tools/mtgbench` is the load generator where the in-process benchmarks do not reach.

## Not in this piece

Rotation with an overlap (R); a per-address **quota** (cumulative bytes per period — it needs
persistence, which the usage file cannot carry without phantom users); the adaptive and
web-profile rate policy (D — it plugs into `setRate`); per-address *events* and Prometheus
labels (cardinality, PII); identifying people behind one address; the panel side.

## Risks

- **A shared address is one client.** CGNAT users collectively get one share and one
  connection budget. Mitigated by being optional and by documenting it; `client-conns`
  and `client-speed` should be set generously where users are mobile.
- **Fair share is adaptive and takes up to a second to react**; a burst from an address
  that was quiet is bounded by its starting half share for at most one tick.
- **Memory:** up to 32,768 entries × a few hundred bytes (limiters are allocated only when
  a cap applies), held in memory for ten minutes after the last connection.
- **Hot path:** one nil check per read and write with no entry; one extra bucket wait where
  a cap applies. Measured, not assumed.
- **Bans are memory-only** and vanish on restart: the safe direction for nothing — which is
  why the docs send an operator to rotation for a real leak.

## Decided by the agent (delegated, 2026-10-07)

Audit these; each was a judgement call, not an instruction.

1. B and R are separate pieces; B builds fair share (the user's "speed share"), R rotation.
2. Automatic per-address controls use the hint classification (loopback/private unkeyed);
   operator-explicit kick/ban use `addressKey` as `kick` does.
3. State exists only with `track-client-ips` or a per-address control on the secret.
4. Table cap 32,768, drop-new, 10 minutes idle retention, 60 s sweep.
5. Fair share = max-min water-filling on measured demand, 1 s tick, demand headroom 1.5×
   and a half-share floor, each address starts at `total/(n+1)`.
6. Per-address waits count into the user's `throttled_ms`.
7. Bans are memory-only, max 4,096, TTL default 1 h / max 30 d, new routes rather than a
   body field on `kick`.
8. No per-address quota and no events in this piece.
9. The panel cannot use these keys yet; this piece targets hand-managed configs.

## Review

To be reviewed before implementation by the advisor and by an independent adversarial
review; the findings and how each was handled are recorded here after those reviews.
