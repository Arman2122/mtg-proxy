# Per-address governance inside one shared secret — design

Date: 2026-10-07 (revision 2 the same day, after an advisor round and an independent
adversarial review that found one blocker and ten majors). Status: approved under delegation
("go all completely by yourself"). Piece B of the shared-secret program (A handshake at scale —
done; **B this piece**; R rotation with an overlap period, straight after B; C bounded
slow-reader queue; D per-address web-profile shaping). B and R are separate pieces on purpose:
B changes the data path, admission and the stats API; R changes both handshake doors, the
config tables, stream closing and the WEB relay.

## The goal, as stated

One secret shared by many people already works on the wire. But the speed limit, the quota, the
ip-limit and the `/stats` counters are all per secret, so one heavy user drains everyone's
share and nobody can see who is using what. Give a shared secret per-**source-address**
controls: a speed share, a connection cap, per-address usage in the stats, and a way to kick
and ban an abusive address.

Retiring a leaked link — rotation with an overlap — is piece R. **Until R ships, the goal of
retiring a leak is not met by this piece**: a ban is a short-term tool; the interim advice in
the docs for a real leak is to re-key the secret.

## Who is an "address"

An address is what the existing per-address features count: an IPv4 address, or an IPv6 /64
(`keyOfAddr`, `address_limit.go`). Consequences this piece states instead of hiding:

- **Carrier-grade NAT shares an address among many people**: a mobile carrier's NAT address
  with 200 users gets one share and one connection budget. Every per-address control is
  optional and off by default.
- **An IPv6 holder with a /56 or /48 has 256 to 65,536 keys.** Per-address controls can be
  multiplied by whoever holds such a prefix. Pair `client-fair` and `client-conns` with
  `ip-limit` (how many addresses a secret may use at once) and ban per /64; a coarser IPv6
  unit is a possible later change.
- **Automatic controls apply only to addresses that stand for one place.** `client-conns`,
  `client-speed` and `client-fair` use the hint cache's classification (`hintKey`): loopback,
  private, link-local, unspecified and multicast addresses are *unkeyed*. Unkeyed streams, and
  streams of an address the table has no room for, are not left ungoverned: they share **one
  per-secret "rest" pseudo-address** that is governed like any other (it holds one share of a
  fair secret and one set of limiters). Behind a loopback carrier that forwards no client
  address every client is therefore one "rest" address, which is exactly what they are.
- **The client address is only as trustworthy as the listener.** On a PROXY-protocol listener
  the address is whatever the sender's header says and this project has no trusted-CIDR list,
  so a holder of the secret who can reach it could forge another member's address to use up
  that member's connection budget or bucket, or to get it banned. The proxy logs a **warning
  at start** when a secret has a per-address control and `proxy-protocol-listener` is on;
  the docs say to use them only behind a front proxy you control.
- **Operator-explicit actions (kick, ban) act on `addressKey` as `kick` does** (an IPv6 address
  acts on its /64). Banning an *unkeyed* address is refused unless the request says
  `"force": true`, because banning `127.0.0.1` behind a loopback carrier bans every client.

## Where things stand

- Speed (`speed`, `speed-up`, `speed-down`) and quota are per secret: a user's connections
  share one token bucket per direction (`speedLimiter`, `speed_limit.go`) enforced in
  `countingConn`. `speedLimiter.wait` reads `Burst()` and then calls `WaitN`; `set` re-derives
  the burst from the rate. If a `set` lowers the burst between those two steps, `WaitN` returns
  an error and **the stream ends** (found by the reviews; reproduced in a scratch program).
  It exists today for any reload that lowers a speed; a per-second re-rating ticker would make
  it routine, so this piece fixes it first (decision 5).
- `ip-limit` caps how many distinct addresses a secret may use at once; nothing caps how many
  connections or how much bandwidth one address may take.
- Per-address state today is a refcount in `addressLedger` (`local[key]` = live connections),
  dropped when the address's last connection closes, so nothing about an address (bytes, a
  bucket, a ban) can live there.
- `kick` closes an address's live streams and nothing more: the device reconnects at once.
- `connected_ips` lists addresses but carries no bytes, no throttle time and no cap.
- The panel regenerates the config file wholesale and writes no key of this piece (see
  "Contracts").

## Decisions

1. **A bounded per-address table with its own lifetime**, keyed by (secret, address): it
   survives reconnects (a bucket must not reset on every new connection) and is dropped after
   the address has been idle ten minutes with no live connection. It holds bytes, times and
   limiters — **not** connection counts.
2. **The connection cap counts from the ledger**, which already refcounts live connections per
   (secret, address) for every address, whether or not a table entry exists. So the cap
   cannot fail open when the table is full and cannot undercount streams that were open when
   it was enabled.
3. **Entries exist only where needed**: when the proxy keeps client addresses
   (`track-client-ips`, which the panel always sets) or the secret has a per-address control.
   Otherwise the data path is a nil pointer. **A panel-managed process therefore gets the
   table** (up to its caps) and pays two atomic adds per read and write; that case is
   benchmarked and has a no-regression bar (see §7).
4. **Caps and overflow.** At most 4,096 entries per secret and 32,768 in all; **drop-new,
   never evict** (eviction would hand a drained bucket back full). A new address past a cap
   joins the secret's "rest" pseudo-address, counted in `clients_overflow`.
5. **Fixed-burst per-address limiters, and a hardened `wait`.** Per-address limiters get a
   burst chosen once when the limiter is created and are re-rated with `SetLimit` only;
   changing the burst means replacing the limiter object (an in-flight wait keeps the old one).
   Independently, `speedLimiter.wait` is hardened to re-chunk and retry when `WaitN` fails
   because the burst shrank under it (the context being done is still an error), which fixes
   the latent reload bug for the secret-level buckets too.
6. **A real fair share, with a static ceiling kept separate.** `client-fair` divides a secret's
   speed limit among its active addresses by a *water level* (below), work-conserving;
   `client-speed` is a separate per-address ceiling bucket. An address held back by its ceiling
   reports its real demand, so the rest goes to addresses that can use it.
7. **One per-address rate hook.** Fair-share limiters are re-rated only through
   `(*clientTable).setRate`, the one place piece D's adaptive/web-profile rate plugs in.
8. **Kick and ban are operator actions**, memory-only, TTL-bound, listed only where addresses
   may be listed, charged like a miss.
9. **Nothing per-address appears as a key under `users`** in `/stats` (the panel bills every
   `users` key as a client); the address list is its own endpoint.

## 1. The table, its locks, its lifetime

`mtglib/client_table.go`. One `clientTable` on `Proxy` (nil-safe: a `Proxy{}` literal in a test
means "off"), with **its own mutex** (`tableMu`), a per-secret index of entries and the
per-secret "rest" pseudo-entry. Entries are read on the data path through atomics only.

```
type clientEntry struct {
    key, name                       // addressKey, secret
    refs                            // streams holding it (under tableMu)
    bytesIn, bytesOut atomic.Int64
    firstSeen time.Time; lastSeen atomic.Int64   // seconds; stored only when it changes
    ceiling  addrLimiter            // client-speed (combined)
    fairSpeed, fairUp, fairDown addrLimiter      // client-fair, one per secret bucket
    // fair-share bookkeeping touched only by the ticker
}
```

- **Lock order (new, stated once):** `reloadMu` → `liveMu` → `tableMu` → (a limiter's own
  lock). The ticker and the sweep take `tableMu` only, copy entry pointers, release it, and
  compute outside it; **neither ever takes `liveMu`**, so neither can stall admissions. The
  60 s sweep walks at most 1,024 entries per `tableMu` hold.
- **Create** inside `tryRegisterConn` (so under `liveMu`), after the ledger admission: if the
  address is keyed and the secret needs an entry (decision 3), acquire it (`refs++`), and
  **initialise its limiters from the current secret set (`p.secrets.Load()` read under
  `liveMu`) before publishing it** — no limiter lock is needed and a reload cannot leave a
  new entry with a stale ceiling. Otherwise the stream joins the secret's "rest" entry.
  The pointer is stored on the stream context as an `atomic.Pointer[clientEntry]`, read on
  every read and write.
- **Release** in `unregisterConn` (`refs--`). **Drop** by the sweep: `refs == 0` and idle ten
  minutes; counters of a dropped-then-recreated address restart (documented).
- **Reload**: `applyLimits` re-rates every entry of each changed secret (ceiling from
  `client-speed`; fair limiters created, kept or set to unlimited according to `client-fair`
  and the secret's speed fields) **and backfills live streams that have no entry** (a control
  a reload enabled must reach connections that were already open, which live for hours):
  under `liveMu`, for each live stream of the secret whose address is keyed, acquire an entry
  and store the pointer. Removing a control sets the matching limiters to unlimited.
- **Secret removed** (`DeleteSecret`/reload drops the name): its entries, its rest entry and
  its bans are dropped with it. A re-key of the same name keeps them.
- **Retention, stated exactly:** an entry holds an address (IPv4, or IPv6 /64) **and the
  secret name it used**, byte counts, two times and limiter state, in process memory, from
  the first connection until ten minutes after the last one closes; never logged, never
  persisted. It exists only where decision 3 says, so a standalone deployment with
  `track-client-ips` off and no per-address control holds none; **with a per-address control
  and tracking off it holds entries anyway** (enforcement needs them), and *listing* them is
  still gated by `track-client-ips`. This is the same exception the budget's address bucket
  has (docs/wiki/Security.md says so).

## 2. The connection cap

`client-conns` (int ≥ 0, 0 = unlimited) in `[secret-limits.<name>]`, `client_conns` on the API.
Checked in `tryRegisterConn` next to the ip-limit check, under `liveMu`, **against the
ledger's live count** (`local[key]`): a new connection from a keyed address that already has
`client-conns` live connections is refused. `tryRegisterConn` now returns a `DenyReason`
instead of a bool; `admit` maps it: ip-limit refusals keep `ip_limit_refused` and
`EventIPLimited`; `DenyClientConns` increments `client_conns_refused` and emits **no event**
(a new event type touches the observer interface and both metric backends; the counter is in
`/stats`); `DenyBanned` (§5) likewise. Refused like ip-limit: closed after the handshake.
Lowering the cap never drops streams. Distinct from `ip-limit` (how many *addresses*): a
Telegram client opens several connections, so set it to a few times that. Unkeyed addresses
are not capped (they are not one place).

## 3. Speed: a ceiling, and a fair share

`addrLimiter` (a small type beside `speedLimiter`, which keeps its behaviour apart from the
hardened `wait`): an atomic pointer to a `rate.Limiter` with a **fixed burst** chosen at
creation (`clamp(T/20, 64 KiB, 4 MiB)` for fair limiters from the secret's configured total
`T`; `clamp(rate/20, 64 KiB, 4 MiB)` for the ceiling), `SetLimit` for re-rating, a nil limiter
= unlimited (one atomic load). Its wait is built on `ReserveN` plus a sleep with an
**injectable clock**, so the reservation's delay is known: it records
`delayed` (waits whose delay was at least 1 ms) and the summed delay. This is both the
fake-clock seam for tests and the **throttle signal**: `time.Since` around `WaitN` cannot be
used (it adds a few hundred nanoseconds to every wait that never slept).

`countingConn` gains a nil-safe per-address step. For a stream with an entry:

- **Cut** each read/write to the smallest burst among the per-address limiters that apply and
  the secret-level chunk (a nil limiter does not cut: an unlimited user still writes once,
  `TestUnlimitedUserWritesOnce`).
- **Wait on the per-address limiters first, then the secret-level ones.** The waits are paid
  from the matching limiters only: a read (upload) pays the ceiling, `fairUp` and `fairSpeed`;
  a write (download) pays the ceiling, `fairDown` and `fairSpeed`; then the secret-level
  `speed` and `speedUp` / `speedDown` as today. Reads stay post-paid and writes pre-paid.
- **Count** bytes in/out on the entry (the only two places bytes are counted); `lastSeen` is
  stamped at second granularity and only when it changed (as `markActive` does).
- A wait on any per-address limiter also adds to the **user's** `throttled_ms` through a
  per-user atomic on `secretStats` added at wait time (entries are swept, so summing entries
  would make the counter go backwards), and to the entry's own throttled time.

**Static ceiling.** `client-speed` (bytes/s, `ParseSpeed` rules, floor 8,000) is the combined
`ceiling` limiter. Setting or lowering it re-rates live entries; removing it sets the limiter
to unlimited — independent of `client-fair`.

**Fair share (`client-fair = true`).** Requires at least one of the secret's `speed`,
`speed-up`, `speed-down` (config validation and the API answer 400 otherwise; the docs
say so). Each configured secret bucket is divided separately: `speed` → `fairSpeed`,
`speed-up` → `fairUp`, `speed-down` → `fairDown`.

- *Participants* of a secret in a direction: its keyed entries with at least one live stream
  that moved a byte in the last 10 s, **plus its rest entry** if it has live streams.
- Every second a ticker (under the proxy context) takes the participants of each fair secret
  (pointers copied under `tableMu`) and, per configured direction with total `T`:
  1. each participant is **throttled** if its fair limiter recorded a delayed wait (≥ 1 ms)
     in the last second, and stays throttled for 3 more ticks (hysteresis); only the fair
     limiter's own delays count — waits at the ceiling or the secret-level bucket do not, so
     an address held by its ceiling reports its true demand;
  2. a non-throttled participant has demand `d` = the rate it actually moved last second; a
     throttled one has demand = +∞;
  3. the **water level** `L` solves `Σ min(d_i, L) = T`: sort the finite demands ascending;
     `remaining = T`, `k = n`; for each finite demand `d`: if `d ≤ remaining/k` then
     `remaining −= d`, `k −= 1`, else stop; `L = remaining/k` (and `L = T` when `k = 0`);
  4. **every participant's fair limiter is set to `L`** (clamped to at least `8,000 B/s` and
     never zero: a zero would read as "unlimited"); the sum of the rates may exceed `T`,
     because the secret-level bucket already enforces `T`. A quiet address can therefore grow
     to `L` at once, nothing is reserved for it, and no capacity is wasted (the reviewed
     alternative of a per-address demand floor wasted up to half of `T`).
- A new participant starts at the current `L` (or `T` if it is alone). Limiters are re-rated
  only through `(*clientTable).setRate(entry, direction, bytesPerSecond)` (the hook D uses).
- Properties, all tested on the pure `waterLevel(total, demands)`, where a participant's
  allocation is `a_i = min(d_i, L)`: `Σ a_i ≤ T`, with equality when some demand exceeds `L`;
  `L ≥ T/n`; **raising one participant's demand never lowers its own allocation and never
  raises anyone else's** (the max-min property: the throttled addresses' level falls when a
  quiet address starts using more — that is the point, not a defect); permutation-invariant;
  `L = T/n` when every demand is ∞; `L = T` when there is one participant; a brute-force
  max-min reference agrees on 10,000 seeded inputs.

## 4. Stats

- **Per-user scalars** (omitempty, inside the existing user object — never new `users` keys):
  `clients` (entries held), `clients_overflow`, `client_conns_refused`; read-back of the limits as
  `client_conns`, `client_speed_limit` (bytes/s int, as `speed_limit`), `client_fair`.
- **A new endpoint** `GET /secrets/{name}/clients?limit=N` (default 100, max 1,000), entries by
  bytes descending, with `total`, `overflow` and the rest entry as a separate object:
  `address` (an IPv4 address or an IPv6 /64 prefix), `connections` (from the ledger),
  `bytes_in`, `bytes_out`, `throttled_ms`, `first_seen`, `last_seen`, the three current
  per-address rates as `speed_limit`, `speed_limit_up`, `speed_limit_down` (0 = none),
  `banned_until`. **Gated exactly like `connected_ips`**: addresses are listed only when
  `track-client-ips` is on; otherwise 200 with the counts only and `"tracking": false`. 404 for
  an unknown secret; behind the bearer token like every route.
- `throttled_ms` keeps meaning "time this user's connections spent held to a limiter" and now
  includes per-address waits (monotonic: a per-user atomic).
- Feature strings: `client-limits` (the three keys/fields), `client-stats`, `client-bans`,
  inserted in sorted position; the hard-coded lists in `proxy_stats_features_test.go` and the
  every-route subtest are edited deliberately.

## 5. Kick and ban

`kick` is unchanged. New, behind the bearer token, memory-only:

- `POST /secrets/{name}/bans` `{"ips":["203.0.113.9", ...], "ttl":"1h", "force": false}` → bans
  the named addresses (as `addressKey`: an IPv6 address bans its /64; the response echoes the
  keys) for `ttl` (default 1 h, max 30 d); **an unkeyed address is refused with 400 unless
  `force` is true**. Under `liveMu` it records the bans and snapshots the matching streams in
  one critical section; the streams are closed after the lock is released (as `Kick` does), so
  no stream registers between the ban and the kick. Response `{"banned":N,"closed":M}`. 409
  `ban list full` past 4,096 bans across all secrets (a ban is an operator action: refuse it
  loudly rather than evict another).
- `GET /secrets/{name}/bans` lists `{"address","expires_at"}` — **gated like `external_ips`**
  (counts only when `track-client-ips` is off). `DELETE /secrets/{name}/bans/{address}` lifts
  one and accepts either an IP or the `/64` form the listing shows. Lock order `liveMu` →
  `banMu`.
- **Enforcement** in `attribute()` right after `checkLimits`, and re-checked inside
  `tryRegisterConn` under `liveMu` (the race window). At attribution a banned address is
  turned away before the server hello exactly like a wrong secret: fronted on FakeTLS,
  `denyObfuscated` on the obfuscated door. The re-check inside `tryRegisterConn` can only fire
  after the server hello and then closes (a rare race, like ip-limit). Because it happens
  after the secret matched, the budget charge is kept and no hint is written (A's rules).
  **On the obfuscated door a ban is charged to `obfsLimiter` like a miss** (`Fail`), so a
  banned client that keeps reconnecting is rate-limited instead of costing an O(N) trial
  decryption for free.
- **A ban lives in memory only**: it survives a reload (a reload rebuilds the secret set, not
  the proxy) but not a restart, and it is dropped when the secret is removed.

## 6. Config, API and contracts

- **Config** (`[secret-limits.<name>]`): `client-conns` (int), `client-speed` (string like
  `speed`), `client-fair` (bool). Parsed and validated like their neighbours (`TypeSpeed`; a
  new `TypeClientConns`, not `TypeIPLimit`, whose messages name "ip-limit"). The new
  `ConfigSecretLimit` fields carry `omitzero` so `Config.String()` is unchanged for every
  config that does not use them (the panel's included). `UnknownKeys` must stay empty for the
  panel's emitted file; an older binary logs the new keys as unknown on `run` and refuses
  them only under `run --check`.
- **API** (`PUT`/`POST /secrets`, read back by `/secrets`, `/stats`, `GET /secrets/{name}`):
  `client_conns`, `client_speed`, `client_fair` in `limitFields`. A zero limit is dropped in
  four places (`GetSecretLimits`, `toConfig`, `handlePutSecrets`, `PutSecret`) and `POST
  /secrets` clears any limit field not sent: every new field is added to `limitFields`,
  `SecretLimits.IsZero`, `fillLimitInfo` and the `handleStats` overlay, with a **reflective
  `IsZero` test that sets each field in turn**. The fork's API is strict
  (`DisallowUnknownFields`): a client must gate on the `client-limits` feature.
- **Panel contract:** nothing under `users` keys; no existing field, route, key or feature
  changes; default `accept-modes` unchanged. **The panel can neither write nor preserve these
  keys**: it regenerates the config file wholesale and its `PUT`/`POST /secrets` bodies carry
  none of them, so a panel-managed inbound cannot use this piece until the panel adopts the
  fields (it does get the stats-only table, decision 3). This piece targets hand-managed
  configs (the live server) and the API fields for future panel adoption. API-set limits
  vanish on the next `POST /reload` (they always have); bans do not.
- **Usage state file untouched**: it is keyed by secret name and any extra top-level key would
  become a phantom billed user.
- **No wire change**: not one byte the proxy sends changes; golden tests untouched.

## 7. Proof

**Test seams.** `addrLimiter` and the ticker take an injectable clock; `waterLevel` is pure;
the fair-share logic is tested at `tick()` level with synthetic observed rates and throttle
flags; address-dependent tests use address-controlled connections (`dialProxyFrom`,
`remoteAddrConn`) with documentation-range addresses (keyed); loopback peers are unkeyed.
Wall-clock fairness assertions flake on Windows and on a 2-vCPU box (the ee speed tests did):
end-to-end fair-share checks use wide bands only ("both progress; sum ≤ T + burst; ratio
between 0.5 and 2").

**Correctness (test first, each sabotage-checked)**

- *speedLimiter hardening*: a hook between `Burst()` and `WaitN` shrinks the burst
  deterministically; before the fix the stream errors, after it the wait completes; a done
  context is still an error.
- *waterLevel* properties and the brute-force reference (above); extremes: one participant, all
  ∞, all zero demand, `T` below `n × 8,000` (clamped, never zero).
- *Tick* (synthetic): a high-demand and a low-demand address — the low one keeps its demand, the
  high one gets the rest (work-conserving); a participant held by its **ceiling** and not
  fair-throttled reports its true demand and the rest goes to the other (the case the
  review found); a new arrival gets the current `L` at once and the others shrink within two
  ticks; hysteresis keeps a throttled address at ∞ for three ticks; the rest entry
  participates; rates never zero.
- *addrLimiter*: a delay of at least 1 ms is recorded as throttle and a sub-millisecond wait is
  not; fixed burst never shrinks under a waiter; replacing the limiter lets an in-flight wait
  finish on the old one.
- *Table*: created only where decision 3 says; refs through connect/disconnect; the sweep keeps
  live and recently idle entries and works in chunks of at most 1,024; per-secret and global
  caps drop new addresses to the rest entry and never evict or reset an existing entry;
  unkeyed peers join the rest entry; IPv4-mapped and same-/64 peers share one; backfill gives a
  live stream an entry when a reload enables a control and removing a control sets the
  limiters to unlimited; entries/bans dropped when the secret is removed and kept on a
  re-key; nil-safe on `Proxy{}`; the documented lock order (a test takes the locks in the
  forbidden order under `-race` to prove the ticker and sweep never take `liveMu`).
- *Connection cap* end to end through the real door: the (cap+1)th connection from an address
  is refused after the handshake **counting streams opened before the cap was enabled**, a
  different address is unaffected, a release frees a slot, lowering the cap never drops
  streams, `client_conns_refused` counts and no `ip_limit_refused` moves, a loopback
  (unkeyed) peer is never capped, the cap holds when the table is full.
- *Static ceiling* against the clock on both doors and both directions (the style of
  `TestSpeedLimitAppliesThroughTheProxy`): two addresses of one secret each held to the cap;
  an unkeyed peer governed as the rest entry; an unlimited secret still writes once; per-address
  waits are paid before secret-level ones (asserted at unit level with `TokensAt` on the shared
  bucket while a per-address wait is pending).
- *Fair share* end to end (wide bands only): two active addresses both progress and their sum
  stays within the secret's limit plus a burst; one idle address does not stall the other.
- *Ban*: a ban refuses at attribution with the same bytes to the cover site as a wrong secret;
  a hook between `attribute` and `tryRegisterConn` proves the re-check refuses a stream that
  slipped past the first check; ban + kick is one critical section (the hook again, not a
  hammer); TTL expiry with a fake clock; unban by IP and by prefix; an unkeyed address is 400
  unless forced; the 4,096 cap returns 409; survives a reload; a banned obfuscated-door client
  is charged to `obfsLimiter`; `GET /bans` is gated.
- *Stats*: nothing new under `users` keys; scalars omitted when zero; `/clients` gated like
  `connected_ips`; ordering and `limit`; `throttled_ms` includes per-address waits and is
  monotonic across a sweep; the existing shape-pinning tests untouched and green.
- *Config/API*: keys known (no `UnknownKeys`), `Config.String()` unchanged for configs not
  using them, the panel-contract test untouched and green, `POST /secrets` neither clears nor
  drops them when sent and clears them when not, the reflective `IsZero` test, `client-fair`
  without a secret speed is rejected, a start warning for a per-address control on a
  PROXY-protocol listener, features sorted.

**Sabotage checks** (each new test fails when its behaviour is removed): drop the per-address
wait; wait on the secret-level bucket first; evict on full; reset a bucket on reconnect; key
unkeyed peers; skip the ban re-check; ban without kick; kick without ban; let `waterLevel`
exceed the total; make a throttled address's demand finite; count ceiling waits as throttle;
let the rate reach zero; mutate the burst under a waiter; list addresses without
`track-client-ips`; take `liveMu` in the ticker; count connections from the table instead of
the ledger.

**Benchmarks (box, same-session A/B of old and new binaries; baseline first, before any code
touches `countingConn`)**: `countingConn` micro-benchmarks and door bulk throughput (ee, dd,
plain; 1 and 16 connections) with address-controlled connections in four cases: **no entry**;
**an entry and no limiter — the panel's case, the most common production case after this piece
ships — with a no-regression bar of 1% on bulk throughput**; a static ceiling above link
speed; fair share on 16 addresses (the ticker's cost). The existing `tools/mtgbench` runs
loopback clients (unkeyed), so address-dependent cases use in-process address stamping, or
mtgbench is extended to send PROXY v2 headers with documentation-range sources. If the
entry-without-limiter case misses its bar, stats-only entries become an explicit opt-in.

## Not in this piece

Rotation with an overlap (R, next); a per-address **quota** (cumulative bytes per period — it
needs persistence the usage file cannot carry without phantom users); the adaptive and
web-profile rate policy (D — it plugs into `setRate`); CIDR bans; per-address *events* and
Prometheus labels (cardinality, PII); identifying people behind one address; the panel side.

## Risks

- **A shared address is one client**: CGNAT users collectively get one share and one
  connection budget. Mitigated by being optional and documented; set `client-conns` and
  `client-speed` generously where users are mobile.
- **Sybil by IPv6 prefix and forged PROXY addresses** are named above and not solved here.
- **Fair share is adaptive**: it reacts within about two seconds; the water level lets a quiet
  address use its share at once, and a burst past the secret-level bucket is bounded by it.
- **Memory:** up to 32,768 entries × a few hundred bytes (limiters allocated only where a cap
  applies), held for ten minutes after the last connection.
- **Hot path:** a nil-pointer load with no entry; two atomic adds with an entry and no limiter;
  one more wait where a cap applies. Measured, not assumed.
- **Bans are memory-only** and vanish on restart; the docs send an operator to rotation (R)
  for a real leak and, until it ships, to re-keying the secret.

## Decided by the agent (delegated, 2026-10-07)

Audit these; each was a judgement call, not an instruction.

1. B and R are separate pieces; B builds fair share (the user's "speed share"), R rotation.
2. Automatic per-address controls use the hint classification; unkeyed and overflow streams
   share one governed "rest" pseudo-address; operator kick/ban use `addressKey`, and an
   unkeyed ban needs `force`.
3. State exists only with `track-client-ips` or a per-address control on the secret — so a
   panel-managed process gets the stats-only table (benchmarked, with a 1% bar).
4. Table caps: 4,096 per secret, 32,768 in all, drop-new, ten minutes idle retention, 60 s
   sweep in chunks of 1,024; the cap counts from the ledger, not the table.
5. Fair share = water level over measured demand (throttled = a ≥ 1 ms reservation delay on
   the fair limiter, 3-tick hysteresis), 1 s tick, every participant's limiter at the level,
   rate clamped to at least 8,000 B/s; the static ceiling is a separate bucket.
6. Fixed-burst per-address limiters, `SetLimit` only; `speedLimiter.wait` hardened to retry.
7. Per-address waits count into the user's `throttled_ms`.
8. Bans are memory-only, max 4,096, TTL default 1 h / max 30 d, new routes rather than a body
   field on `kick`, charged like a miss on the obfuscated door; listing gated.
9. A per-address control with tracking off still holds (address, secret name) entries for ten
   minutes (documented exception, like the budget's address bucket).
10. No per-address quota, no events, no CIDR bans in this piece.
11. The panel cannot use these keys yet; this piece targets hand-managed configs.

## Review

Reviewed before implementation by the advisor (adopted: separate ceiling and fair buckets;
the burst race; benchmarking the panel's case; taking the table's per-tick work off `liveMu`)
and by an independent adversarial review (one blocker, ten majors). The blocker — a fair-share
estimator that wasted bandwidth (a per-address demand floor) and whose "throttled" signal was
undefined — became the water level with a reservation-delay signal. Majors adopted: the burst
race (fixed bursts and a hardened `wait`), a zero allocation reading as unlimited (clamped), the
table's per-secret cap and the governed "rest" pseudo-address for unkeyed and overflow streams,
lock order and the stale-ceiling race (limiters initialised before publication; reload
backfills live streams), counting the cap from the ledger, the panel's case in the benchmarks,
banning unkeyed addresses (`force`), `GET /bans` privacy and the retention exception, and the
refusal plumbing (`DenyReason`, no new event, charge a miss on the obfuscated door).
