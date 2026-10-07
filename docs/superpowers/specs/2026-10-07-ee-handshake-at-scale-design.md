# ee handshake at thousands of secrets — design

Date: 2026-10-07 (revision 2 the same day, after an independent review).
Status: approved under delegation ("go all completely by yourself", 2026-10-07).
Piece A of a four-piece program (A handshake at scale, B per-address governance
inside one secret, C bounded slow-reader queue, D per-address web-profile
shaping). Each piece has its own spec, plan and before/after numbers.

## The goal, as stated

Keep the ee (FakeTLS) handshake fast when one process hosts thousands of
secrets, and keep an attacker from turning that cost against the proxy.

`fake.ReadClientHelloMulti` runs one HMAC-SHA256 per hosted secret. Measured
standalone on the 2 vCPU Skylake bench box (no SHA-NI): 3.9 µs per secret, so
3.6 ms per unmatched hello at 1,000 secrets and 20 ms at 5,000.

## Where things stand

- **The cost is per candidate and cannot be shared.** HMAC is keyed from its
  first byte, so no work on the hello is common to two secrets. A candidate
  costs `3 + ceil((L+9)/64)` SHA-256 blocks, where `L` is the length of the
  re-synthesised hello record (5-byte record header + 4-byte handshake header +
  body) and the 9 is SHA-256's padding (one `0x80` byte and an 8-byte length):
  inner hash = 1 key-pad block + `ceil((L+9)/64)` message blocks, outer hash = 2
  blocks. 12 blocks for a 517-byte hello; 1,028 for the largest accepted
  (65,540 bytes). The part that precomputing the key pads can remove is 2 of 12
  blocks (17%), plus seven allocations. (From the source; measured below.)
- **Real cost per block varies 25× across CPUs.** About 325 ns on the bench box
  (no SHA-NI); about 13 ns with SHA-NI (a review measured a 64 KiB HMAC at
  13.4 µs). Any budget in fixed "nominal" units is therefore off by an order of
  magnitude on one of them.
- **The FakeTLS door has no budget.** The dd door has `obfuscatedLimiter` (per-IP
  failure budget, public listeners only); the ee door has only the worker pool,
  which caps concurrent connections, not CPU spent per hello.
- **A hello is attacker-sized**, up to 65,540 bytes, so one hello at 1,000
  secrets is on the order of 0.3 s of CPU on the bench box, roughly a hundred
  times the 3.6 ms figure. The SNI gate runs first, but the cover SNI is public
  (it is in every link).
- **Per-address limits are forgeable or evadable.** A PROXY-protocol listener
  takes the client address from a header any peer can send, and an IPv6 /48 holds
  65,536 /64s. A per-address budget alone is not a CPU bound.
- **Returning clients pay the same as strangers.** Nothing remembers that
  203.0.113.7 matched `alice` a minute ago.
- **ee is one door of two.** The dd door has its own limiter; this piece bounds
  the ee door only.

## Decisions

1. **Split the matcher into parse and verify.** `fake` exposes the primitives;
   `mtglib` owns the policy. `ReadClientHelloMulti` stays as a thin wrapper with
   identical behaviour.
2. **A hint cache is the large lever; precomputed pads are the small one.**
3. **Two budgets, one ceiling.** A per-address bucket stops a single source; a
   process-wide bucket is the real bound and holds against many sources and
   forged addresses.
4. **Budgets are in real CPU.** Cost is calibrated once at start (ns per block on
   this machine), so "25% of the cores" means 25% of the cores.
5. **Queue briefly, then front.** An unhinted scan that cannot be afforded waits
   up to 150 ms for budget (smoothing bursts and restarts) before it is fronted.
6. **A scan cap.** A hello larger than 128 blocks (about 8 KiB) is never hinted
   and never scanned: it is fronted. Real clients send about 0.5 to 2 KiB.
7. **A charge is kept unless the whole handshake succeeds.** A replay, a denied
   user or a refused admission keeps its charge.
8. **Over budget means fronted, never closed.** Same bytes as a no-match; the
   time to the first fronted byte differs (stated honestly below).

## 1. The matcher

`mtglib/internal/tls/fake` gains:

- `ParseClientHelloFor(conn, hostnames) (*Parsed, error)` — everything
  `ReadClientHelloMulti` does before its candidate loop (parse, SNI gate, keep the
  re-synthesised bytes), same errors. `Parsed` carries `Hello`, `MatchedHost` and
  `Blocks()`.
- `NewCandidate(key []byte) *Candidate` — the key's HMAC inner and outer states
  after the pad block, exported with `MarshalBinary` once. Plain `hmac.New` is the
  defensive fallback when the state cannot be exported or the key exceeds the
  64-byte block (secret keys are 16 bytes); `NewPlainCandidate` is the reference
  path, always plain.
- `(*Parsed).Verify(c *Candidate, skew time.Duration) bool` — one HMAC, the same
  constant-time compare and timestamp-skew rule as today, zero allocations on the
  precomputed path (per-`Parsed` scratch digests, not a pool).

`ReadClientHelloMulti(conn, secrets, hostnames, skew)` becomes: parse, then
`NewPlainCandidate` + `Verify` in order. Same results, same errors, same partial
result (`MatchedIndex: -1`, `MatchedHost` set) on no match.

`secretSet` gains, built once per reload by `buildSecretSet`: `cands`, `candIdx`
(the hosted secrets in name order **with later duplicates of an earlier key
removed**: a duplicate is already unreachable on this door, so removing it changes
no attribution) and `candByName`. The per-handshake `secretKeys` slice goes away.
Every new field is nil-safe: a hand-built `Proxy{}` literal in a test acts as
"hints off, budget off".

## 2. The hint cache

Client address (the key `limiterKey` already builds: IPv4, or the IPv6 /64) to the
names of up to 16 secrets that recently matched from it, most recent first.

- **Use.** Only for a keyed address and only when `Blocks() <= 128`. The hinted
  candidates are verified first, in order; a hit finishes the handshake; a miss
  falls through to the scan over the rest. Worst case 16 × 128 blocks, bounded.
- **Unkeyed addresses get no hints**: loopback, private, link-local, unspecified,
  and "no address". Behind a carrier that does not forward the client address
  they would be one shared key.
- **Write.** Only after the whole success path: verified, not a replay, `attribute`
  accepted **and `admit` accepted** (throttle, `ip-limit`, address ledger). A probe,
  a replay, a denied or throttled user never writes a hint.
- **Names, not indices.** A hint resolves through `candByName` against the
  snapshot the handshake loaded, so a reload that re-sorts, removes or re-keys a
  secret never produces a wrong match: a removed name is skipped; a re-keyed name
  resolves to its new key (a hello under the old key simply falls through).
- **Bounds and flushing.** At most 32,768 addresses in total across the two
  generations; when full, new addresses are **not** added until the 30-minute
  rotation drops the older generation. A valid-secret holder who controls many
  addresses can therefore keep new hints out, never evict existing ones.
- **Privacy (budget).** Separately from hints, the per-address budget bucket
  (§3) holds an address (IPv4, or IPv6 /64) and the time of its last scan — no secret
  name — in process memory for 30 to 60 minutes after its last unhinted scan,
  whatever `hints` and `track-client-ips` say; it is never logged, exported or
  persisted. The older dd limiter keeps anonymous IP-keyed buckets the same way.
  `per-ip-ms = 0` keeps none, at the price of per-source isolation. What
  `track-client-ips` governs (`connected_ips`, `last_ip`, the address ledger) is
  unchanged.
- **Privacy (hints).** The cache holds address → secret name (the panel's names are
  emails) in process memory for 30 to 60 minutes after the last use. Never logged,
  exported or persisted; gone on restart. It **follows `track-client-ips`** by
  default (on exactly when the operator has already chosen to keep client addresses
  past a connection — the panel always does), so a standalone deployment keeps the
  documented promise that no address outlives its connection. `hints = true|false`
  overrides it either way.
- **What it cannot do.** It never makes a wrong secret verify: every hinted
  candidate passes through the same `Verify`. A prober never matches, so it can
  neither read nor plant a hint.

## 3. The budget

**Units and calibration.** Cost is in SHA-256 blocks. The first proxy a process
builds measures `ns/block` on this machine **on the primitive the budget charges**:
an HMAC-SHA-256 over a 517-byte buffer, counted as the 12 blocks `Blocks()` gives
for such a hello (not bulk hashing, which reads 1.3 to 2.6× low because it skips
the per-candidate overhead: about 13 ns/block bulk against about 34 ns/block for a
real verify on a SHA-NI machine; the bench box is about 340 ns/block). The reading
is the minimum of three short runs of about 4 ms, clamped to 10 ns to 2 µs; it is
of the plain path, so a pad path only makes the real cost lower: conservative,
never loose. Every later proxy reuses it (a
package-level `sync.Once`: the test suite builds hundreds of proxies); tests inject
the constant. `GOMAXPROCS` is read once at start. The calibrated value is logged at
start and reported as `ns_per_block` in `/stats`, so an operator can see what the
budget believes a block costs.

**Two buckets** over the *unhinted scan* (hinted verification is exempt):

| | Per address | Process-wide |
|---|---|---|
| Key | the hint key; unkeyed addresses skip this bucket | one |
| Refill | `per-ip-ms` (default 50) ms of scan CPU per second; **0 disables this bucket** | `cpu-percent` (default 25) % of `GOMAXPROCS` cores |
| Burst | 4 s of refill, but never below `4 × candidates × 12` blocks | 1 s of refill, same floor |

Both refill rates are `real CPU time ÷ ns/block`: 50 ms/s at 325 ns/block is about
154,000 blocks/s; 25% of 2 cores is about 1,540,000 blocks/s.

**Admission** of an unhinted scan: `cost = candidates × clamp(Blocks, 12, 128)`.
The floor of 12 makes admission size-uniform (a 100-byte hello cannot slip in where
a real 517-byte hello is refused); the cap of 128 is the scan cap. The buckets are
virtual-schedule token buckets in `float64` (no integer overflow after idle):
tokens may go negative, to at most `-rate × 150 ms`. A reservation computes the
delay the later of the two buckets implies; if that exceeds **150 ms** the scan is
refused and neither bucket changes; otherwise both are charged and the handshake
waits the delay (cancelled by the connection's context) and scans. Both buckets are
reserved under one lock, so there is no partial reservation to roll back.

The burst floor depends only on the candidate count (the 12 is the cost floor), never
on the hello's own size, so a flood of large hellos cannot raise its own cap. The
per-address map never resets buckets by rotating when it fills: once it holds its
maximum (32,768 addresses) a new address simply has no per-address entry and uses the
process-wide bucket only; the 30-minute rotation is by timer.

**Settlement.** The reservation is single-use. It is **refunded in full only when
the whole handshake succeeds** (verified, replay check passed, `attribute` and
`admit` accepted). `admit` runs immediately after the door returns, before the
client's next flight (`proxy_serve.go:69-75`), so no client round trip is spent
holding a reservation. A replay of a captured valid hello, a disabled, expired or
over-quota user, a throttled or `ip-limit`-refused user, and a scan that matched
nothing all keep their charge. Refunds go to the bucket object and are capped at
its burst.

**Refusal.** Over-budget, oversized or wait-exceeded: the proxy fronts the
connection with the host the SNI named, through the same call a no-match uses.
No scan, no close.

**Modes.** `enforce` (default) refuses. `observe` runs the **identical shadow
accounting** — a granted scan deducts from the buckets, a would-refuse leaves them
unchanged, a successful handshake refunds — and differs only in that it never waits
and never refuses: it counts the decision and scans anyway. It additionally counts
hellos that were over budget **and then matched a secret** (`over_budget_matched`):
the legitimate traffic `enforce` would have fronted, which is what a canary needs to
see. (Without the shadow deduction the buckets would never drain and observe would
report nothing.) `off` disables the budget and the scan cap; the hint cache is
governed by `hints`.

**What an attacker can and cannot do, stated plainly.** To lock new users out, an
attacker must keep the process-wide bucket empty, which costs them about
`cpu-percent` of this proxy's real CPU in scan work (before this change the same
effort could starve everything, relays included). While it lasts, a client **with
no hint** is fronted after at most 150 ms and retries; hinted clients, established
streams and the data path are unaffected. Behind a carrier that hides client
addresses, the per-address layer is off by construction and only the process-wide
bucket applies. A legitimate user behind an address whose bucket a flooder has
drained is treated the same way unless a hint exists. This is the accepted
degradation; `observe` mode and its counters exist so an operator can see whether
it ever touches real users before enforcing.

**Timing.** A refused hello and a no-match hello send the cover site the same
bytes; the time before the first fronted byte differs (a no-match is fronted after
its scan, a refusal after at most 150 ms). Scan time already varied with hello size
and with the SNI gate before this change; this adds one more such dependence and
`Security.md` says so.

## 4. The handshake flow

`doFakeTLSHandshake` after the change:

1. Load the snapshot once; parse and apply the SNI gate (unchanged).
2. If `mode != off` and `Blocks() > 128`: count `oversized`, front (observe: count
   and continue).
3. If hints apply (keyed address, `Blocks() <= 128`, `hints` on): verify the
   hinted candidates in order; on a hit continue at 6.
4. Reserve the budget for the remaining candidates; refused → count `denied_ip`
   or `denied_global`, front. Otherwise wait the delay.
5. Scan the remaining candidates; no match → `unmatched`, keep the charge, front
   (today's no-match exit).
6. Replay check, `attribute`, server hello (unchanged). After `admit` succeeds,
   write the hint and refund the reservation.

## 5. Config, API surface, contracts

- **Config**: a new optional `[defense.handshake-budget]` table: `mode`
  (`"enforce"` default, `"observe"`, `"off"`), `per-ip-ms` (default 50, 0–1000),
  `cpu-percent` (default 25, 1–100), `hints` (default: the value of
  `track-client-ips`). Restart-only: a
  reload re-reads secrets, not this table. The panel never writes `[defense]`. An
  older binary logs the table as unknown keys on `run` and refuses it only under
  `run --check` (`internal/cli/run_proxy.go:336`, `internal/cli/run.go:37`).
  `ProxyOpts` zero values mean the defaults above (enforce), for library
  embedders; documented.
- **`/stats`**: a new top-level object `faketls_handshake`, omitted until the door
  has counted something (the pattern `obfuscated` follows), with `hinted`,
  `scanned`, `unmatched`, `denied_ip`, `denied_global`, `oversized`,
  `over_budget_matched`, the flag `enforced` and `ns_per_block` (the calibrated
  block cost). Nothing is added under `users`
  (the panel bills every `users` key as a client). `features` gains
  `handshake-budget`.
- **Counter outcomes (in `enforce` mode each handshake past the SNI gate
  increments exactly one of these; in `observe` a would-refuse counter moves
  together with `scanned` or `unmatched`, tested as pairs):** matched by a hint → `hinted`; matched by the scan → `scanned`; scanned,
  no match → `unmatched`; refused by a bucket → `denied_ip` (checked first) or
  `denied_global`; above the scan cap → `oversized`. `over_budget_matched` is an
  extra counter, only in observe mode, on a match that the budget would have
  refused. In observe mode `denied_*` and `oversized` count what enforce would
  have refused. A replay or a denied user after a match counts as its match.
- **Not changed:** every byte the proxy sends for an accepted hello; the
  golden-byte tests (untouched); release asset names; API endpoints and fields;
  existing config keys; default `accept-modes` (`["ee"]`); doppelganger pacing.
  What does change: under `enforce`, a hello that would have been accepted can be
  fronted (the accepted degradation above), and a hello above 128 blocks is no
  longer scanned.
- **Docs:** `example.config.toml`, `Configuration.md`, `Security.md` (including the
  fronting-indistinguishability list), `Monitoring.md`, `Multi-User-and-API.md`
  (feature list and table), and the README `/stats` sample.

## 6. Proof

**Test seams.** The budget takes `now func() time.Time` and the calibrated
`ns/block`; the hint cache has a `rotate()` hook; address-dependent tests use the
harness's address-controlled connections (`remoteAddrConn`, `connWithAddr`), since
the default harness peers are loopback and therefore unkeyed.

**Correctness (test first, each sabotage-checked)**

- *Differential*: the old matcher (kept in the test file as the reference) and the
  new one agree on 10,000 seeded random scenarios (right key at every position,
  wrong key, duplicate keys, fresh and skewed timestamps, hellos 100 B to 64 KiB
  including fragmented ones), and a fuzz target does the same on arbitrary bytes.
- *RFC 4231* cases 1 to 4 (keys under 64 bytes), copied from the RFC, through the
  pad path and the plain path.
- *Hints*: hit skips the scan; stale and wrong hints fall through; nothing written
  by a failed, replayed, denied or throttled handshake; a reload that removes or
  re-keys a name never mis-attributes; 16 users behind one address; the cap drops
  new addresses without evicting old ones; loopback, private and nil addresses get
  none; IPv4-mapped and same-/64 peers share one key.
- *Budget* (unit level, fake clock): burst then refill per address; **10,000
  distinct /64s are stopped by the process-wide bucket**, and so are forged
  addresses; the 150 ms queue admits a small herd and refuses past it; a charge is
  refunded exactly once and only on whole success (replay, denied user and
  `admit`-refused keep it); burst floors scale with the candidate count;
  size-uniform cost; oversized refused; **observe mode's shadow accounting drains the
  buckets like enforce (a flood in observe mode, then a legitimate hello during it,
  moves `over_budget_matched`)**; a full per-address map gives a new address no
  entry (process-wide bucket only) and never resets an existing one; the burst floor
  is `4 × candidates × 12` whatever the hello size; unkeyed peers use only the
  process-wide bucket; `per-ip-ms = 0` disables only the per-address bucket; tokens never go
  below the debt floor or above burst; no overflow after a long idle.
- *End to end*: a refused hello and a no-match hello deliver identical bytes to
  the cover site (bytes only; timing is stated, not proven); the shared-address
  scenario (one client retrying a removed secret, new users behind the same
  address are admitted on a first or second attempt with a hint, or after the wait
  without one); every counter moves exactly once per outcome.

**Sabotage checks** (each new test fails when its behaviour is removed): drop the
hint write; drop the hint read; refund before the replay check; drop the
process-wide bucket; key the process-wide bucket per address; skip the duplicate
removal; write the hint before `admit`; rotate-on-fill instead of drop-new; skip
the scan cap; make a refusal close instead of front.

**Benchmarks, first commits of the branch, before any optimisation**

- A realistic hello builder with a size option, a timestamp option and
  fragmentation for sizes over one record, added next to, not inside,
  `testclient.ClientHello` (`tools/mtgbench` depends on that one; its baselines
  must not move; a pinned golden proves it).
- `BenchmarkReadClientHelloMulti` in `fake_test`: N ∈ {1, 10, 100, 1,000, 5,000},
  target first / last / unmatched, hello 517 B and 4 KiB, with allocations. It
  reproduces the 3.9 µs per secret figure in-tree.
- A secrets-count dimension on `BenchmarkDoorHandshake` for `ee-unpaced` (`dd` as
  the control).
- Runs on the bench box under its rules (`/root/mtg-bench` only, cross-compiled,
  short, cleaned up), before and after, and again after any hot-path change.

**Acceptance**

- A hint hit at N = 5,000 costs within 1.3× of N = 1.
- Precomputed pads stay only if they cut ns per candidate by at least 10% on the
  box (a scratch run on a SHA-NI machine measured 395 → 217 ns at 517 B, 7 → 0
  allocations, so the rule is expected to pass; the box decides).
- A flood test shows zero verifications once the budget is spent, bounded by the
  process-wide ceiling for many addresses.
- Existing tests pass untouched except the four hard-coded feature lists and the
  tests that enumerate them, which gain `handshake-budget`; the full gate (pinned
  `golangci-lint` 2.13.2, `go test -count=2 -race ./...`) is green locally. No CI
  is claimed: GitHub Actions is disabled for the account.

## Risks

- **A legitimate unhinted client is fronted during a sustained attack or behind a
  busy address.** Accepted and stated; mitigated by hints, the 150 ms queue,
  size-uniform cost, a ceiling in real CPU, and `observe` mode with
  `over_budget_matched`.
- **Calibration under load.** The minimum of three runs resists noise; a bad
  reading is clamped; the effect is a budget off by a factor, never a failure.
- **A timing difference between hinted and scanned success** is visible only to the
  authenticated client itself.
- **Hint memory and privacy** are bounded and in-process only; see section 2.
- **One process per inbound.** The panel runs one proxy process per inbound, so
  the "process-wide" ceiling is per inbound, not per host; `cpu-percent` is
  applied independently in each.

## Not in this piece

Per-address governance, rotation, the doppelganger queue and shaping (B, C, D);
parallel scanning across cores; a cap on hello size at the parser (it would break
fronting parity; the scan cap fronts instead); the dd door.

## Decided by the agent (delegated, 2026-10-07)

Audit these; each was a judgement call, not an instruction.

1. The budget is on by default, in `enforce` mode, with real-CPU calibration, a
   150 ms queue and a scan cap — after the review showed fixed nominal units and
   instant refusal made a cheap lock-out possible.
2. Defaults: `per-ip-ms` 50, `cpu-percent` 25, queue 150 ms, scan cap 128 blocks,
   cost floor 12 blocks.
3. Loopback, private, link-local, unspecified and unaddressable peers are unkeyed:
   process-wide bucket only, no hints.
4. 16 hints per address, 32,768 addresses, 30-minute rotation, drop-new when full.
5. Hinted verification is exempt from the budget but bounded by the scan cap.
6. A match refunds only after the whole handshake succeeds.
7. Precomputed pads are conditional on a measured 10% gain.
8. The new `/stats` object is `faketls_handshake`; the feature string is
   `handshake-budget`; `hints` defaults to the value of `track-client-ips` (the
   privacy switch), so only deployments that already keep addresses keep hints.
10. The per-address budget bucket keeps an address (no secret name) in memory for
    30 to 60 minutes even when `track-client-ips` is off, so the repo's "no address
    outlives its connection" promise is scoped to what `track-client-ips` governs
    and the budget's retention is documented instead of removed (found by the
    Task 7 review; `per-ip-ms = 0` keeps none). Alternative not taken: make the
    per-address layer follow `track-client-ips` — it would leave one source able to
    lock out everyone on a standalone deployment.
9. The first deployment to the live server runs `mode = "observe"`, and `enforce` is
   enabled only once `over_budget_matched` stays near zero (release-notes item, not
   code).

## Review

Reviewed before implementation by the advisor (adopted: process-wide ceiling,
shared-address evidence and counters, `observe` mode, benchmark-first ordering) and
by an independent adversarial review (one blocker, seven majors; all addressed in
this revision: B1 → real-CPU calibration, queue, `observe` default of evidence;
M1 → settle-on-success; M2/M3 → scan cap, uniform cost, burst floors; M4 → timing
stated; M5 → `over_budget_matched`; M6 → unkeyed private ranges, `per-ip-ms = 0`;
M7 → drop-new, write after `admit`).
