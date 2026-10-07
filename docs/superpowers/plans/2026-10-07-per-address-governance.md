# Per-address governance inside one shared secret — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Per-source-address controls inside one shared secret: a connection cap, a static speed ceiling, a work-conserving fair share, per-address stats on their own endpoint, and memory-only kick+ban — without breaking the panel's contracts.

**Architecture:** A bounded per-address table with its own lifetime and lock (`clientTable`, with a per-secret "rest" pseudo-address); fixed-burst `addrLimiter`s driven by an injectable clock; the connection cap counted from the existing address ledger; a pure `waterLevel` plus a 1 s ticker for fair share, whose throttle signal is a rate-independent duty; bans enforced at attribution; stats on a new gated endpoint and as omitempty scalars inside the user object. Benchmarked on the bench box with address-stamped connections, same-session A/B.

**Tech Stack:** Go 1.26.8, `golang.org/x/time/rate` (already used), testify, the repo's `entryHarness`, `dialProxyFrom`/`remoteAddrConn`, `benchstat`.

**Spec:** `docs/superpowers/specs/2026-10-07-per-address-governance-design.md` (revision 3; read it first — it explains why each rule exists, and two independent reviews shaped it).

## Global Constraints

- Additive only. No release-asset name, API endpoint, existing JSON field, existing config key or `[secrets]`/`[secret-ad-tags]`/`[secret-limits]` change; default `accept-modes` stays `["ee"]`; no wire change (golden tests, `panel_contract_test.go`, the shape-pinning tests stay **untouched**); the usage-state file is untouched (a new top-level key would become a phantom billed user).
- `/stats`: nothing new as a **key** under `users`. New data = omitempty scalars inside the user object (`clients`, `clients_overflow`, `client_conns_refused`, read-back `client_conns`, `client_speed_limit`, `client_fair`) and the `GET /secrets/{name}/clients` and `/bans` routes. Addresses are listed only when `track-client-ips` is on (as `connected_ips`); counts are never gated. Feature strings `client-bans`, `client-limits`, `client-stats`, inserted sorted (`client-bans` < `client-ip-activity` < `client-ips` < `client-limits` < `client-stats` < `faketls`); the hard-coded lists in `mtglib/proxy_stats_features_test.go` and the every-route subtest are edited deliberately; `proxy_stats_handshake_test.go`'s `handshake-budget` neighbour pin stays green.
- Config `[secret-limits.<name>]`: `client-conns` (int ≥ 0), `client-speed` (string, `ParseSpeed` rules, floor 8,000 B/s), `client-fair` (bool; needs at least one of `speed`/`speed-up`/`speed-down`, else config validation and the API answer an error). API fields `client_conns`, `client_speed`, `client_fair` in `limitFields`; **every new field also goes into `SecretLimits`, `IsZero`, `fillLimitInfo`, the `handleStats` overlay, `GetSecretLimits`, `toConfig`, `handlePutSecrets` and `PutSecret`** (a `POST /secrets` clears any field not sent), proven by a reflective test that sets each field in turn. New `ConfigSecretLimit` fields carry `omitzero` so `Config.String()` is unchanged for configs that do not use them. A new `TypeClientConns` (not `TypeIPLimit`).
- Constants (spec §1-§5, verbatim): table caps **4,096 entries per secret** (`min(4,096, ip-limit)` when `ip-limit` is set) and **32,768** in all, drop-new, never evict; idle retention **10 min** with no live stream; sweep every **60 s**, at most **1,024 entries per `tableMu` hold**; fair-share tick **1 s**; throttle = **duty ≥ 25%** of the tick (wall time in waits at the fair limiter or the secret-level bucket, **never the ceiling**), hysteresis **3 ticks**, released when the observed rate falls below **L/2**; `L` floored, **≥ 1 B/s (the floor only raises a computed 0 to 1; no larger clamp)**, never zero; fixed per-address burst `clamp(T/20, 64 KiB, 4 MiB)` (fair) and `clamp(rate/20, 64 KiB, 4 MiB)` (ceiling); participants = keyed entries with a live stream that moved a byte in the last **10 s** plus the rest entry; every entry with a live stream is set to `L`; the rest entry is one participant with **no ceiling**; ban cap **4,096**, TTL default **1 h**, max **30 d**; `/clients` limit default **100**, max **1,000**.
- **Lock order:** `reloadMu` → `liveMu` → `tableMu` → (a limiter's own lock). The ticker and the sweep take `tableMu` only (never `liveMu`); `banMu` is inner to `liveMu`; `GET /clients` takes `liveMu` then `tableMu`.
- **Automatic controls** (`client-conns`, `client-speed`, `client-fair`) use `hintKey`'s classification: unkeyed peers (loopback, private, link-local, unspecified, multicast) are never capped by `client-conns` and join the secret's **rest** entry; operator **kick/ban** act on `addressKey` and an unkeyed ban is a 400 without `"force": true`.
- Every new `Proxy`/`streamContext`/`secretSet` field is nil-safe and means "off" (tests build `Proxy{}` literals). A nil per-address limiter does not cut a transfer: an unlimited user still writes once (`TestUnlimitedUserWritesOnce`).
- Address-dependent tests use address-controlled connections (`dialProxyFrom`, widened to `testing.TB` where a benchmark needs it; `remoteAddrConn`) with documentation-range addresses (203.0.113.x, 198.51.100.x, 2001:db8::/32 — keyed); loopback peers are unkeyed. Fair-share timing assertions are wide bands only; the algorithm is tested synthetically.
- Every new test is **sabotage-checked**: break the behaviour, watch the test fail, restore; record each result in the task report.
- Gate before each task's final commit: `go build ./... && go vet ./...`, `go test -count=1 -race` on the packages touched (whole-tree gate at the end), pinned `golangci-lint` 2.13.2 (`config verify` THEN `run`), `golangci-lint fmt ./...` after scripted edits. LF endings. Commit messages carry no attribution lines. Never push, tag or merge. Windows exhausts local ports with rapid repeated test runs: no 40-run loops.

## Review Focus

Failure modes the spec implies that no single headline test covers; each has a pinned test in the owning task.

1. **Unkeyed and overflow streams** are governed as the rest entry, never silently ungoverned and never capped by `client-conns`. Tasks 6, 7, 9.
2. **IPv4-mapped and same-/64 peers** share one entry and one connection count. Tasks 6, 7.
3. **A refused connection leaves the ledger exactly as it was** (ban re-check, `client-conns`, ip-limit, entry acquisition: the stated order). Task 3 and 7.
4. **A reload that enables, changes or removes a control with streams already open** reaches those streams (backfill; unkeyed streams join the rest entry; removal sets limiters to unlimited). Tasks 9, 12b.
5. **A secret removed or re-keyed**: entries, rest entry and bans dropped on removal, kept on a re-key. Tasks 6, 11a.
6. **`throttled_ms` stays monotonic** across a sweep that drops entries. Task 8.
7. **A 4-connection address against a 1-connection address** converge under fair share (the secret-level bucket splits per connection; a 1-against-1 test cannot see the failure). Tasks 12a, 12b.

---

### Task 1: Harden `speedLimiter.wait` (an existing latent bug)

**Files:**
- Modify: `mtglib/speed_limit.go`
- Test: `mtglib/speed_limit_wait_test.go`

**Interfaces:**
- Produces: `(*speedLimiter).wait(ctx, n) error` keeps its signature and behaviour except: when `WaitN` fails because the limiter's burst shrank between `Burst()` and `WaitN` — detected as `ctx.Err() == nil && piece > current.Burst()`, never by matching an error string — it re-reads the burst and retries the remaining bytes in smaller pieces instead of returning the error. A done context is still returned as an error. A test-only seam (an unexported package variable called between `Burst()` and `WaitN`) lets a test shrink the burst deterministically.

- [ ] **Step 1: Failing tests**: `TestWaitSurvivesABurstShrunkUnderIt` (the seam shrinks the burst after `Burst()` is read; before the fix `wait` returns an error, after it returns nil having charged every byte); `TestWaitStillFailsWhenTheContextIsDone`; `TestWaitWithoutAShrinkIsUnchanged` (n over burst is paid in pieces as before). Run: FAIL.
- [ ] **Step 2: Implement** the retry and the seam.
- [ ] **Step 3: Sabotage**: remove the retry; treat any `WaitN` error as retryable (a done context must then fail the context test). Restore.
- [ ] **Step 4:** `go test -count=1 -race ./mtglib/ -run 'Speed|Wait'` and lint; commit `fix(mtglib): a limiter re-rated under a wait no longer ends the stream`.

### Task 2: `addrLimiter` — fixed burst, one injected clock

**Files:**
- Create: `mtglib/addr_limiter.go`
- Test: `mtglib/addr_limiter_test.go`

**Interfaces:**
- Produces: `type addrClock struct{ now func() time.Time; sleep func(ctx context.Context, d time.Duration) error }` (zero value = real clock); `type addrLimiter struct{…}`; `func (l *addrLimiter) install(bytesPerSecond int64, burst int)` (creates or **replaces** the limiter object; `0` stores nil = unlimited; an in-flight wait keeps the old object); `func (l *addrLimiter) setRate(bytesPerSecond int64)` (`SetLimitAt(now)` only — never creates, no-op when nil, clamps to ≥ 1 and never 0); `func (l *addrLimiter) chunk(n int) int` (one atomic load; nil does not cut); `func (l *addrLimiter) wait(ctx context.Context, n int) (waited time.Duration, err error)` (built on `ReserveN(now)` + the injected sleep, `CancelAt(now)` when the context ends mid-sleep; pays in burst-sized pieces; `waited` = total sleep); `func (l *addrLimiter) bytesPerSecond() int64`; `func fairBurst(total int64) int` = `clamp(total/20, 64 KiB, 4 MiB)` and `func ceilingBurst(rate int64) int` = `clamp(rate/20, 64 KiB, 4 MiB)`.
- Every call on the limiter uses the injected clock (mixing `SetLimit`'s `time.Now` with a fake clock corrupts token state).

- [ ] **Step 1: Failing tests** (fake clock): `TestAnUnlimitedAddrLimiterNeitherCutsNorWaits`; `TestWaitSleepsTheReservationDelay` (known rate, known n, exact `waited`); `TestSetRateNeverCreatesNorZeroes` (nil stays nil; 0 becomes 1); `TestTheBurstNeverShrinksUnderAWaiter` (many goroutines wait while `setRate` hammers; none errors); `TestInstallReplacesTheObjectAndAnInFlightWaitFinishes`; `TestCancelledSleepRefundsItsReservation`; `TestChunkCutsToTheBurst`; `TestFairBurstAndCeilingBurstClamps`. Run: FAIL.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Sabotage**: use `SetLimit` instead of `SetLimitAt(now)`; let `setRate` create a limiter; mutate the burst in `setRate`; skip `CancelAt`; drop the ≥ 1 clamp. Each fails a named test. Restore.
- [ ] **Step 4:** gate; commit `feat(mtglib): a per-address limiter with a fixed burst and an injected clock`.

### Task 3: `DenyReason` plumbing (no behaviour change)

**Files:**
- Modify: `mtglib/secret_limits.go` (`DenyClientConns`, `DenyBanned` reasons and their `String()`), `mtglib/proxy_serve.go` (`attribute`, `tryRegisterConn`, `admit`), `mtglib/proxy_entry.go` (both doors), tests that call them
- Test: `mtglib/proxy_deny_reason_test.go`

**Interfaces:**
- Produces: `tryRegisterConn` and `attribute` return a `DenyReason` (a bool wrapper `attribute`/`tryRegisterConn` may remain for existing callers) so each door and `admit` can tell refusals apart; `admit` maps `DenyIPLimit` to today's `ip_limit_refused` + `EventIPLimited` exactly as before; `DenyClientConns` and `DenyBanned` increment their own counters and emit **no** event; the obfuscated door can call `obfsLimiter.Fail(policy, ip)` for `DenyBanned`. No behaviour changes in this task: nothing yet produces the two new reasons.

- [ ] **Step 1: Failing tests**: the existing ip-limit refusal still increments `ip_limit_refused`, emits `EventIPLimited` and closes the stream (pinned before the refactor); `String()` of the new reasons; the check order and rollback seam: a test-only hook between steps proves a refusal at a later step releases what an earlier step took (written now against the current two steps: ledger admit then registration). Run: FAIL (undefined) then the refactor.
- [ ] **Step 2: Implement**; `registerFakeStream` (`proxy_reload_test.go`) only needs the signature change.
- [ ] **Step 3: Sabotage**: map `DenyIPLimit` to nothing; forget the rollback. Restore.
- [ ] **Step 4:** whole `./mtglib` suite + gate; commit `refactor(mtglib): admission refusals carry their reason`.

### Task 4: Pure `waterLevel`

**Files:**
- Create: `mtglib/water_level.go`
- Test: `mtglib/water_level_test.go`

**Interfaces:**
- Produces: `const demandInfinite = int64(math.MaxInt64)`; `func waterLevel(total int64, demands []int64) int64` — spec §3 step 3 verbatim (sort finite demands ascending; `remaining = total`, `k = n`; for each finite demand `d`: if `d <= remaining/k` then `remaining -= d`, `k--` else stop; `L = remaining/k`, `L = total` when `k == 0`), floored, **≥ 1 (the floor only raises a computed 0 to 1; `L ≥ floor(total/n)` and exceeds it whenever some demand is far enough below it; never assert `L ≤ total/n`)**, `n == 0` returns `total`. Allocation of participant i is `min(d_i, L)`.

- [ ] **Step 1: Failing tests**: a brute-force max-min reference (repeated division, floored the same way) agrees on 10,000 seeded random inputs; `Σ min(d_i, L) ≤ T` and equals `T` up to the floor remainder (< n) when some demand exceeds `L`; `L ≥ T/n` (floored, ≥ 1); **raising one demand never lowers that participant's own allocation and never raises anyone else's**; permutation-invariant; all ∞ gives `T/n`; one participant gives `T`; all-zero demands; `T = 8,000` with 4,097 participants gives 1; ties. Run: FAIL.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Sabotage**: raise the floor to 8,000 (the rejected clamp); drop the `k == 0` case; use `min` instead of the ascending loop; stop at the first finite demand. Each fails a named test. Restore.
- [ ] **Step 4:** gate; commit `feat(mtglib): the fair-share water level, pure`.

### Task 5: Benchmark harness with address-stamped connections; box baseline

**Files:**
- Modify: `mtglib/proxy_client_ips_test.go` (widen `dialProxyFrom` to `testing.TB`), `mtglib/door_bench_test.go`
- Create: `mtglib/counting_conn_bench_test.go`, `benchmarks/results/2026-10-07-per-address-baseline.txt` (controller)

**Interfaces:**
- Produces: `BenchmarkCountingConn/<read|write>/<noentry>` (a `countingConn` over an in-memory pair; entries do not exist yet — the sub-benchmark names are fixed now so Tasks 8-9 add `entry`, `ceiling`, `fair` rows with identical names for the A/B); door bulk rows `BenchmarkDoorBulk/<ee-unpaced|dd|plain>/conns=<1|16>/addr=stamped` using `dialProxyFrom` with a documentation-range address (keyed), verified byte-exact.

- [ ] **Step 1:** Write the benchmarks; each verifies what it measures (byte counts). Run once locally with a tiny `-benchtime`.
- [ ] **Step 2: Commit** `bench: counting conn and door bulk throughput with stamped addresses`.
- [ ] **Step 3 (controller):** cross-compile, run on the box under its rules (`/root/mtg-bench` only, `-test.count 12` for the A/B, short runs), save the raw baseline with a header, clean up the box; commit `bench: per-address baseline on the box`.

### Task 6: The client table

**Files:**
- Create: `mtglib/client_table.go`
- Modify: `mtglib/proxy.go` (field), `mtglib/stream_context.go` (`atomic.Pointer[clientEntry]`), `mtglib/proxy_serve.go` (`tryRegisterConn`, `unregisterConn`), `mtglib/proxy_secrets.go` (`applyLimits` backfill, secret removal), maintenance (`startMaintenance`: the 60 s sweep)
- Test: `mtglib/client_table_test.go`, `mtglib/proxy_client_table_test.go`

**Interfaces:**
- Produces (6a, pure): `type clientEntry` (spec §1), `type clientTable`, `func newClientTable(clock addrClock) *clientTable` (nil-safe methods); `func (t *clientTable) acquire(name string, key addressKey, keyed bool, init entryInit) *clientEntry` — unkeyed or over a cap (per-secret `min(4,096, ip-limit)`, global 32,768) returns the secret's **rest** entry and counts `clients_overflow`; limiters of a new entry are initialised from `init` (the ceiling rate and the fair totals) **before** it is published; `release(e)`; `sweep(now, maxPerHold int) int` (drops `refs == 0` and idle ≥ 10 min, ≤ 1,024 per `tableMu` hold, snapshotting keys across holds); `snapshot(name string) []*clientEntry` (pointers copied under `tableMu`); `dropSecret(name string)`; counters `clients(name)`, `overflow(name)`.
- Produces (6b, wiring): entry created in `tryRegisterConn` **after** `ledger.admit`, only where the spec's decision 3 says (`track-client-ips` or the secret has a per-address control), `init` read from `p.secrets.Load()` under `liveMu`; pointer stored on the stream context; `release` in `unregisterConn`; the sweep runs from the maintenance loop; `applyLimits` backfills live streams without an entry (keyed → acquire; unkeyed → rest) under `liveMu`; `DeleteSecret`/removal drops entries and bans.

- [ ] **Step 1: Failing tests (6a)**: created only for a keyed address when needed; refs through acquire/release; **drop-new at both caps never evicts or resets an existing entry** (fill to the per-secret cap, an existing entry keeps its bytes and limiter); the per-secret cap follows `ip-limit`; unkeyed peers join the rest entry and `overflow` counts connections; IPv4-mapped and same-/64 keys share one entry (Review Focus 2); the sweep keeps live and recently idle entries, drops idle ones, and processes ≤ 1,024 per hold (a test holds the lock hook); `dropSecret`; nil receiver safe; a test holds `liveMu` and asserts `snapshot`, `sweep` and the ticker's table reads finish within a timeout (the lock-order proof). Run: FAIL.
- [ ] **Step 2: Failing tests (6b)**: end-to-end through the real door with address-controlled connections: an entry exists after connect and its `refs` falls on close; a secret with neither tracking nor a control creates none; a reload that adds a control backfills an already-open keyed stream and an already-open unkeyed stream (rest entry); removing a secret drops its entries; a re-key keeps them; `Proxy{}` literals work. Run: FAIL.
- [ ] **Step 3: Implement** 6a then 6b (two commits are fine); add the sweep to `startMaintenance`.
- [ ] **Step 4: Sabotage**: evict on full; reset a bucket on reconnect; skip the rest entry for unkeyed; take `liveMu` in the sweep; create entries when nothing needs them; skip the backfill; keep entries on secret removal. Each fails a named test. Restore.
- [ ] **Step 5:** whole `./mtglib` + gate; commits `feat(mtglib): a bounded per-address table with its own lifetime` and `feat(mtglib): the table joins admission, release and reload`.

### Task 7: `client-conns`, from the ledger — config, API, read-back

**Files:**
- Modify: `mtglib/secret_limits.go` (`SecretLimits.ClientConns`, `IsZero`), `mtglib/proxy_serve.go` (the cap in `tryRegisterConn`), `mtglib/proxy_api.go` (`limitFields`, `parse()`, `fillLimitInfo`, `handleStats` overlay), `mtglib/proxy_stats.go` (`UserStatsJSON`/`SecretInfo` fields `client_conns`, `client_conns_refused`; `FeatureClientLimits`), `mtglib/proxy_secrets.go` (`toConfig` keeps it), `internal/config/{parse.go,config.go,type_client_conns.go}`, `mtglib/proxy_stats_features_test.go`
- Test: `mtglib/client_conns_test.go`, `internal/config/client_limits_config_test.go`

**Interfaces:**
- Produces: the check order inside `tryRegisterConn` is **(1) ban re-check (not yet), (2) `client-conns`: refuse when the keyed address's ledger `local[key] >= cap`, read BEFORE `ledger.admit`, (3) `ledger.admit` (ip-limit), (4) entry acquisition**; refusal returns `DenyClientConns`: closed after the handshake like ip-limit, `client_conns_refused` counted, no event; unkeyed addresses are never capped. `FeatureClientLimits = "client-limits"` (the three keys/fields; `client_speed` and `client_fair` land in Tasks 9/12b but the feature string is added here and described as "client-conns now").

- [ ] **Step 1: Failing tests**: e2e through the real door with address-controlled connections — the (cap+1)th connection from an address is refused after the handshake **counting streams opened before the cap was enabled by a reload**; a different address is unaffected; closing a stream frees a slot; lowering the cap never drops streams; `client_conns_refused` counts and `ip_limit_refused` does not move; a loopback peer is never capped; the cap holds when the table is full; refused attempts leave the ledger empty. Config: key known (no `UnknownKeys`), `Config.String()` unchanged for configs not using it, `TestPanelEmittedConfigIsAccepted` untouched; negative value rejected naming the key; **the reflective `IsZero` test** sets each `SecretLimits` field in turn; `POST /secrets` clears `client_conns` when not sent and keeps it when sent; `PUT /secrets` round trip; the four hard-coded feature lists. Run: FAIL.
- [ ] **Step 2: Implement** across the files listed (the explorer's checklist: `SecretLimits`, `IsZero`, `limitFields`, `parse()`, `fillLimitInfo`, the overlay, `TomlConfig` mirror, `ConfigSecretLimit` with `omitzero`, `GetSecretLimits`, the new `TypeClientConns`).
- [ ] **Step 3: Sabotage**: count after `ledger.admit` (off by one); count from the table instead of the ledger; cap unkeyed peers; drop `ClientConns` from `IsZero`; drop it from `toConfig`; skip the rollback. Each fails a named test. Restore.
- [ ] **Step 4:** whole `./mtglib ./internal/config ./internal/cli` + gate; commit `feat: client-conns, a per-address connection cap counted from the ledger`.

### Task 8: The per-address step in `countingConn`; the panel's case

**Files:**
- Modify: `mtglib/counting_conn.go` (`withClient(*atomic.Pointer[clientEntry])`, nil-safe), `mtglib/proxy_serve.go` (the call site), `mtglib/proxy_stats.go` (`clientThrottledNanos` on `secretStats`, summed into `throttled_ms`), `mtglib/counting_conn_bench_test.go` (add the `entry` rows)
- Test: `mtglib/counting_conn_client_test.go`

**Interfaces:**
- Produces: per read/write, when the stream's entry pointer is non-nil: cut to the smallest burst among the entry's limiters and the secret-level chunk; **wait per-address limiters first (ceiling, then fair), then the secret-level ones**; count bytes in/out on the entry (the only two places bytes are counted); `lastSeen` stamped at second granularity and only when it changed; bracket every wait that feeds the fair-share duty (fair limiters and secret-level buckets, **not** the ceiling) with a per-direction **blocked-interval tracker** on the entry (`enter`/`leave`: the count of blocked streams, the time it last rose from zero, the time accumulated; `snapshot(now)` returns the blocked time in the window **including an interval still open**, and resets the window) — a union over streams, credited incrementally while a wait lasts (`speedLimiter.wait` returns no waited time, so `countingConn` brackets the secret-level wait itself); add every per-address wait to a per-user atomic `clientThrottledNanos` (monotonic) included in `throttled_ms`. A nil entry pointer or nil limiters: unchanged behaviour, one extra atomic load. `newCountingConn`'s 5-argument signature is unchanged (builder).

- [ ] **Step 1: Failing tests**: bytes in/out land on the entry; `lastSeen` stamped once per second; an unlimited user with an entry still writes once; per-address waits precede secret-level ones (unit level: while a per-address wait is pending, `TokensAt` on the shared bucket is untouched); `throttled_ms` includes per-address waits and **stays monotonic when the sweep drops the entry**; the blocked-interval tracker counts waits at the fair limiter and the secret-level bucket and **not** the ceiling; **two streams blocked at once count once** (a union), a wait that outlasts a snapshot window is credited **while it lasts** (snapshot with the interval still open), and the window resets; nil-safe. Run: FAIL.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Sabotage**: wait on the secret-level bucket first; count ceiling waits in the duty; sum entries instead of the per-user atomic; stamp `lastSeen` every call. Restore.
- [ ] **Step 4: Gate**, then **(controller)** the panel-case A/B on the box: `BenchmarkCountingConn` and the door bulk rows, old binary vs new binary alternating (≥ 10 each), benchstat; bar "no significant regression above 2-3% at p < 0.05" for `noentry` and for **`entry` with no limiter** (the panel's case); if `entry` misses, stats-only entries become an opt-in (stop and rule). Commit `feat(mtglib): per-address byte counts and waits in the counting conn` and the results.

### Task 9: `client-speed` — the static ceiling

**Files:**
- Modify: `mtglib/secret_limits.go`, `proxy_api.go`, `proxy_stats.go`, `proxy_secrets.go` (`applyLimits` re-rates and backfills), `internal/config/*` (as Task 7, with `TypeSpeed`), `mtglib/client_table.go` (entry init)
- Test: `mtglib/client_speed_test.go`, `internal/config` additions

**Interfaces:**
- Produces: `SecretLimits.ClientSpeedBytesPerSecond` (+ `IsZero`, API `client_speed`, read-back `client_speed_limit`, TOML `client-speed`); a new entry's `ceiling` limiter installed from the secret's current limits before publication (`ceilingBurst`); `applyLimits` re-rates live entries (`setRate`) and installs/removes the limiter when the key appears/disappears, and backfills streams without an entry; removing the key sets the limiter to unlimited **independent of `client-fair`**.

- [ ] **Step 1: Failing tests**: against the clock on both doors and both directions (the style of `TestSpeedLimitAppliesThroughTheProxy`): two addresses of one secret each held to the cap, a third unkeyed peer governed as the rest entry **with no ceiling** (it is not capped by `client-speed`); an unlimited secret still writes once; a reload that adds, lowers, raises and removes the key reaches streams already open; config/API/`IsZero`/read-back as in Task 7. Run: FAIL.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Sabotage**: give the rest entry a ceiling; leave live streams ungoverned on reload; share one limiter across addresses; make removal not unlimited. Restore.
- [ ] **Step 4:** gate; commit `feat: client-speed, a per-address ceiling`.

### Task 10: Stats — scalars, `GET /secrets/{name}/clients`

**Files:**
- Modify: `mtglib/proxy_api.go` (route + handler), `mtglib/proxy_stats.go` (`UserStatsJSON`/`SecretInfo` scalars `clients`, `clients_overflow`; `FeatureClientStats`), tests listing features and routes
- Test: `mtglib/client_stats_test.go`

**Interfaces:**
- Produces: `GET /secrets/{name}/clients?limit=N` per spec §4 (entries by bytes descending; `total`, `overflow`, the rest entry as a separate object; fields `address`, `connections` (from the ledger), `bytes_in`, `bytes_out`, `throttled_ms`, `first_seen`, `last_seen`, `speed_limit`, `speed_limit_up`, `speed_limit_down`, `banned_until`); **addresses listed only when `track-client-ips` is on**, otherwise 200 with counts and `"tracking": false`; 404 unknown secret; behind the bearer; scalars omitempty inside the user object, never new `users` keys; `FeatureClientStats = "client-stats"`.

- [ ] **Step 1: Failing tests**: gating exactly like `connected_ips` (with tracking off no address appears anywhere, scalars still do); ordering and `limit` (default 100, max 1,000); the rest entry object; nothing new under `users` keys (`TestStatsResponseShapeUnchanged` & co untouched and green); scalars omitted when zero; `TestStatsAndSecretsAgreeAboutAUser` still green; the route exists (every-route subtest) and the feature lists. Run: FAIL.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Sabotage**: list addresses without tracking; emit a key under `users`; unsorted output; no limit cap. Restore.
- [ ] **Step 4:** gate; commit `feat: per-address usage on its own endpoint`.

### Task 11: Kick and ban

**Files:**
- Create: `mtglib/proxy_bans.go`
- Modify: `mtglib/proxy_api.go` (routes), `mtglib/proxy_serve.go` (`attribute`, the `tryRegisterConn` re-check), `mtglib/proxy_entry.go` (obfuscated door `Fail`), `mtglib/handshake_hints.go` (`forget(ip)`), `mtglib/proxy_stats.go` (`FeatureClientBans`)
- Test: `mtglib/proxy_bans_test.go`

**Interfaces:**
- Produces (11a): the ban table (`banMu`, inner to `liveMu`, keyed by `addressKey`, capped at 4,096 across secrets, TTL default 1 h max 30 d with an injectable clock); `POST /secrets/{name}/bans {"ips":[…],"ttl":"1h","force":false}` (400 for an unkeyed address without `force`; 409 `ban list full`; under `liveMu` it records the bans and snapshots matching streams, closing them after the lock is released; response `{"banned":N,"closed":M}`; address keys echoed only when tracking is on; **forgets the addresses' hints**); `GET /secrets/{name}/bans` (gated like `external_ips`); `DELETE /secrets/{name}/bans/{address...}` (IP or `/64` form); bans dropped with the secret.
- Produces (11b): enforcement in `attribute` right after `checkLimits` (`DenyBanned`: fronted on FakeTLS before `SendServerHello`, `denyObfuscated` on the obfuscated door) and re-checked inside `tryRegisterConn` under `liveMu` as step (1); on the obfuscated door `DenyBanned` is charged `obfsLimiter.Fail(policy, ip)`; budget charge kept and no hint written (A's rules); `FeatureClientBans = "client-bans"`.

- [ ] **Step 1: Failing tests**: a ban refuses at attribution with **the same bytes to the cover site as a wrong secret**; a hook between `attribute` and `tryRegisterConn` proves the re-check refuses a stream that slipped past the first check; ban+kick is one critical section (the hook, not a hammer); TTL expiry (fake clock); unban by IP and by `/64`; an unkeyed address is 400 unless forced; the 4,096 cap returns 409; survives a reload; dropped when the secret is removed, kept on a re-key; a banned obfuscated-door client is charged to `obfsLimiter`; `GET /bans` gated (addresses only with tracking); a ban forgets hints; the route/feature lists. Run: FAIL.
- [ ] **Step 2: Implement** 11a then 11b (two commits).
- [ ] **Step 3: Sabotage**: skip the re-check; ban without kick; kick without ban; echo keys without tracking; fail to forget hints; skip `Fail`; list addresses ungated. Restore.
- [ ] **Step 4:** gate; commits `feat: bans, memory-only and TTL-bound` and `feat: a banned address is turned away like a wrong secret`.

### Task 12: Fair share

**Files:**
- Create: `mtglib/fair_share.go`
- Modify: `mtglib/client_table.go`, `mtglib/proxy_secrets.go` (`applyLimits` creates/removes fair limiters), `mtglib/secret_limits.go`, `proxy_api.go`, `internal/config/*` (`client-fair`, validation), `mtglib/proxy_stats.go` (read-back `client_fair`), `proxy.go` (ticker under the proxy context)
- Test: `mtglib/fair_share_test.go`, `mtglib/fair_share_e2e_test.go`

**Interfaces:**
- Produces (12a): `func (t *clientTable) tick(now time.Time, secret fairSecret) ` computing, per configured direction, each participant's duty (the entry's blocked-interval tracker snapshot ÷ the tick, a union over streams, an interval still open counted), throttled/hysteresis/`L/2` release, demand (observed rate, or `demandInfinite`), `waterLevel`, and `setRate(entry, direction, L)` for **every entry of the secret with a live stream** (participants and idle-but-connected alike), the rest entry as one participant with no ceiling; inputs (duties, observed rates, live flags) are injectable so tests are synthetic; `setRate` never creates a limiter.
- Produces (12b): the 1 s ticker goroutine under the proxy context (stops with `Shutdown`); `client-fair` in config/API (error when no secret speed is configured: config validation and a 400); `applyLimits` installs fair limiters (`fairBurst(T)`) when `client-fair` is on and sets them to unlimited when it is turned off or the secret's speed fields are removed; `FeatureClientLimits` now covers `client-fair`.

- [ ] **Step 1: Failing tests (12a, synthetic, no clocks)**: a high-demand and a low-demand address (the low keeps its demand, the high gets the rest); an address held by its **ceiling** and not fair-throttled reports its true demand and the rest goes to the other; **a 4-connection and a 1-connection address both downloading, the secret-level bucket splitting 4:1 and each fair limiter starting at `T`, converge to `T/2` within a few ticks** (fails if secret-level waits are not in the duty); a downloader that pauses releases the other at once (`L/2` rule); a new arrival is set to the current `L` and the others shrink within two ticks; hysteresis holds ∞ for three ticks; an entry with a live stream but no bytes for 10 s is still set to `L`; the rest entry participates and carries no ceiling; rates never zero and no clamp lifts them (the floor only raises a computed 0 to 1); duty is rate-independent (identical outcome at 1 MB/s and 100 MB/s); `applyLimits` toggling `client-fair`. Run: FAIL.
- [ ] **Step 2: Failing tests (12b)**: the ticker starts/stops with the proxy; config/API/`IsZero`/read-back/validation (`client-fair` with no speed is an error); a reload that turns fair on/off reaches open streams (Review Focus 4); **e2e, wide bands only**: a 4-connection address against a 1-connection address (real door, unpaced harness, a fake Telegram that pushes) both progress, the sum stays within the secret's limit plus a burst, and the ratio of their bytes falls inside 0.5-2; one idle address does not stall the other. Run: FAIL.
- [ ] **Step 3: Implement** 12a then 12b (two commits).
- [ ] **Step 4: Sabotage**: count only the fair limiter's waits in the duty (the 4:1 test must fail); count ceiling waits; clamp `L` up to 8,000; set only participants; drop the pause release; zero rate; let `setRate` create limiters. Each fails a named test. Restore.
- [ ] **Step 5:** whole `./mtglib ./internal/...` + gate (no webrelay loops); commits `feat(mtglib): fair-share ticker` and `feat: client-fair, a work-conserving per-address share`.

### Task 13: Warning, docs, whole-branch gate, box A/B, report (controller task)

**Files:**
- Modify: `internal/cli/run_proxy.go` (the PROXY-listener start warning), `example.config.toml`, `docs/wiki/{Configuration,Limits-and-Quotas,Multi-User-and-API,Monitoring,Security}.md`, `README.md`
- Create: `benchmarks/results/2026-10-07-per-address-after.txt`, `benchmarks/results/2026-10-07-per-address-report.md`

- [ ] **Step 1: Warning**: at start, when any secret has `client-conns`/`client-speed`/`client-fair` and `proxy-protocol-listener` is on, log a warning that client addresses come from the PROXY header and these controls are only as trustworthy as the front proxy; test with a capturing logger; sabotage by removing the condition.
- [ ] **Step 2: Docs** (each passage re-read against the code): the three config keys with defaults and the CGNAT / IPv6-/56 / PROXY-listener / unkeyed-rest caveats next to each; the retention exception (an entry holds an address **and the secret name** for ten minutes after the last stream, even with tracking off, whenever a per-address control exists); the stats object, `/clients`, `/bans`, features; bans are memory-only and not a rotation (interim advice for a real leak: re-key the secret; piece R follows); the panel cannot write these keys yet.
- [ ] **Step 3: Gate**: `golangci-lint config verify` then `run`; `go build ./... && go vet ./...`; `go test -count=2 -race ./...`; `govulncheck`; frozen files byte-identical to `origin/main`.
- [ ] **Step 4: Box A/B** (same-session alternation, ≥ 10 each, benchstat): `noentry`, `entry` (panel case), `ceiling`, `fair on 16 addresses`; calibrate nothing new; record honest limits.
- [ ] **Step 5:** report + raw data; whole-branch independent review (fable); fix wave; commit `bench: per-address governance, before and after`.
