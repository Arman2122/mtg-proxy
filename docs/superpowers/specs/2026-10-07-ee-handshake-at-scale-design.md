# ee handshake at thousands of secrets — design

Date: 2026-10-07. Status: approved under delegation ("go all completely by
yourself", 2026-10-07); independently reviewed before any code (see the end).
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
  costs `3 + ceil((len+9)/64)` SHA-256 blocks: about 12 for a real 517-byte
  hello, about 1,030 for a 64 KiB one. The only part that can be removed per
  candidate is the two key-pad blocks (about 17% of 12), plus about six
  allocations. (Derived from the source; the benchmarks in this piece measure
  it.)
- **The FakeTLS door has no budget at all.** The dd door has `obfuscatedLimiter`
  (per-IP failure budget, public listeners only); the ee door has only the worker
  pool, which caps concurrent connections, not CPU spent per hello.
- **A hello is attacker-sized**, up to 65,531 bytes (`maxClientHelloSize`), kept
  that large on purpose so a prober's hello is fronted like any website's. At
  1,000 secrets one 64 KiB hello is on the order of 0.3 s of CPU (estimate,
  measured below), roughly a hundred times what the 3.6 ms figure suggests.
- **Per-address limits are forgeable or evadable.** A PROXY-protocol listener
  takes the client address from a header any peer can send, and an IPv6 /48
  holds 65,536 /64s. A per-address budget alone is therefore not a CPU bound.
- **Returning clients pay the same as strangers.** Nothing remembers that
  203.0.113.7 matched `alice` a minute ago, so every reconnect scans from the
  top of the name-sorted list.

## Decisions

1. **Split the matcher into parse and verify.** `fake` exposes the primitives;
   `mtglib` owns the policy (hints, budget). `ReadClientHelloMulti` stays as a
   thin wrapper with identical behaviour, so its callers and the golden tests
   do not change.
2. **A hint cache is the large lever; precomputed pads are the small one.** The
   cache makes a returning client O(hints). Precomputing pads is kept only if it
   earns its keep (decision rule below).
3. **Two budgets, one ceiling.** A per-address bucket stops a single source; a
   process-wide bucket, sized as a fraction of `GOMAXPROCS`, is the real bound
   and holds against many sources and forged addresses.
4. **Charge work, not attempts.** Both budgets are in SHA-256 blocks, so a large
   hello costs what it costs and a small deployment never notices the budget.
5. **Over budget means fronted, never closed.** The refusal takes exactly the
   exit a no-match takes today, so a prober learns nothing.

## 1. The matcher

`mtglib/internal/tls/fake` gains:

- `ParseClientHelloFor(conn, hostnames) (*Parsed, error)` — everything
  `ReadClientHelloMulti` does before its candidate loop: parse, SNI gate, keep
  the re-synthesised hello bytes. `Parsed` carries `Hello`, `MatchedHost` and
  `Blocks()`, the SHA-256 blocks one candidate costs for this hello.
- `NewCandidate(key []byte) *Candidate` — the key's HMAC inner and outer states
  after the pad block, exported with `MarshalBinary` once. If the hash cannot
  export its state (FIPS-restricted builds), the candidate silently uses plain
  `hmac.New`; the two paths are tested against each other and against RFC 4231.
- `(*Parsed).Verify(c *Candidate, skew time.Duration) bool` — one HMAC, zero
  allocations on the fast path, the same constant-time compare and the same
  timestamp-skew rule as today.

`ReadClientHelloMulti(conn, secrets, hostnames, skew)` becomes: parse, then
`NewCandidate` + `Verify` over the list in order. Same results, same errors,
same partial result (`MatchedIndex: -1`, `MatchedHost` set) on no match.

`secretSet` gains, built once per reload by `buildSecretSet`:

- `cands []*fake.Candidate` and `candIdx []int` — the hosted secrets in name
  order **with later duplicates of an earlier key removed**. A duplicate key is
  already unreachable on this door (first match wins), so removing it changes no
  attribution and saves its HMAC. `candIdx[i]` is the index into `secrets`.
- `candByName map[string]int` — name to position in `cands`, for hints.

The per-handshake `secretKeys` slice in `doFakeTLSHandshake` goes away.

## 2. The hint cache

A bounded two-generation map (the shape `obfuscatedLimiter` already uses):
client address (IPv4, or the IPv6 /64) to the names of up to 16 secrets that
recently matched from it, most recent first.

- **Use.** After the parse and the SNI gate, the hinted candidates are verified
  first, in order. A hit finishes the handshake. A miss falls through to the scan
  over the remaining candidates, skipping the ones just tried.
- **Write.** Only after the whole success path: verified, not a replay, and
  `attribute` accepted the user. A probe, a replayed hello or a denied user never
  writes a hint.
- **Names, not indices.** A hint resolves through `candByName` against the
  snapshot the handshake loaded, so a reload that re-sorts, removes or re-keys a
  secret is handled by the ordinary verification failing, never by a stale index.
- **Several per address.** CGNAT puts hundreds of users behind one address; 16
  is the starting bound (an internal constant, tuned by the measured hit rate).
- **Bounds.** 32,768 addresses per generation, rotated every 30 minutes; memory
  is proportional to addresses actually seen. Held in memory only, never logged,
  never exported, never persisted.
- **What it cannot do.** It never makes a wrong secret verify, because every
  hinted candidate passes through the same `Verify`. A prober never matches, so
  it can neither read nor plant a hint.

## 3. The budget

Units are SHA-256 blocks at a nominal 250 ns each (the Skylake box measures
about 325 ns; modern CPUs about 40 ns, so the nominal figure is conservative
there). Nominal, not calibrated: deterministic and testable with a fake clock.

Two token buckets over the **unhinted scan** (hinted verification is exempt: at
most 16 candidates, about 200 blocks):

| | Per address | Process-wide |
|---|---|---|
| Key | IPv4 /32, IPv6 /64; loopback addresses and "no address" are not keyed | one |
| Refill | `per-ip-ms` (default 50) ms of nominal work per second, i.e. 200,000 blocks/s | `cpu-percent` (default 25) % of `GOMAXPROCS` cores, i.e. 1,000,000 blocks/s per core |
| Burst | 4 s of refill | 1 s of refill |

- **Admission** of an unhinted scan of `cost = candidates × Blocks()`: refused
  when `cost` exceeds either burst, or either bucket holds fewer than `cost`
  tokens. Otherwise `cost` is **reserved** from both.
- **Refund.** A scan that matches gives its whole reservation back: a legitimate
  handshake costs the budget nothing, as in the dd door. A scan that fails keeps
  it. The reservation also bounds in-flight work: the number of simultaneous
  unhinted scans cannot exceed what the buckets hold.
- **Refused scan.** The proxy fronts the connection with the host the SNI named,
  through the same call a no-match uses. No scan, no close, no distinguishable
  difference.
- **Loopback is not keyed.** Behind a TCP carrier that does not forward the
  client address, every peer presents 127.0.0.1; a per-address bucket there would
  be one shared bucket that one attacker empties for everyone (the reason the dd
  limiter is armed only on public listeners). Loopback peers are held to the
  process-wide bucket only.
- **Enforcement mode.** `mode = "enforce"` (default) refuses; `mode = "observe"`
  counts what it would have refused and scans anyway; `mode = "off"` disables
  the budget (the hint cache stays: it cannot hurt).

**Accepted degradation, stated plainly.** During a large multi-source attack the
process-wide bucket runs dry and a client **with no hint** is fronted until it
refills; clients with a hint are unaffected, and the clients' own retry brings
the others in. A legitimate user behind an address whose bucket a flooder has
drained is fronted the same way, unless a hint exists, and a user who joins a
busy CGNAT address stays fronted until that address's bucket recovers (about
0.3 s per 60k-block scan at 5,000 secrets).

## 4. The handshake flow

`doFakeTLSHandshake`, after the change:

1. Load the snapshot once; parse the hello and apply the SNI gate (unchanged).
2. Verify the address's hinted candidates in order. On a hit, go to 6.
3. Compute the cost of scanning the rest; ask the budget. Refused: front.
4. Scan; on a match, refund and go to 6; otherwise keep the charge and front.
5. (no-match exit, unchanged: front with the SNI host.)
6. Replay check, `attribute`, server hello (unchanged). After `attribute`
   succeeds, write the hint.

## 5. Config, API surface, contracts

- **Config**: a new optional `[defense.handshake-budget]` table: `mode`
  (`"enforce"` default, `"observe"`, `"off"`), `per-ip-ms` (default 50),
  `cpu-percent` (default 25). The panel never writes `[defense]`. An older binary
  that finds the table logs it as an unknown key on `run` and refuses it only
  under `run --check` (verified in `internal/cli/run_proxy.go:336`,
  `internal/cli/run.go:37`), so nothing the panel renders changes.
- **`/stats`**: a new top-level object `faketls_handshake`
  (`hinted`, `scanned`, `unmatched`, `denied_ip`, `denied_global`, `enforced`).
  Counters are additive; no key is added under `users` (the panel treats every
  `users` key as a client). `features` gains `handshake-budget`.
- **No wire change.** Not one byte the proxy sends or accepts changes; the
  golden-byte tests pass untouched. No release asset, API endpoint, existing
  field or existing config key changes. Default `accept-modes` stays `["ee"]`.
- **Doppelganger pacing is untouched.**

## 6. Proof

**Correctness (test first, each sabotage-checked)**

- *Differential*: the old matcher (kept in the test file as the reference) and
  the new one agree on 10,000 seeded random scenarios: right key at every
  position, wrong key, duplicate keys, skewed and fresh timestamps, truncated and
  fragmented hellos, hellos from 100 B to 4 KiB.
- *RFC 4231*: the precomputed-pad HMAC reproduces the published HMAC-SHA256
  vectors copied from the RFC (not computed locally), and the plain fallback
  path is forced and compared to it.
- *Hints*: a hit skips the scan (counted by a candidate-verification counter); a
  stale or wrong hint falls through and still matches; a hint written by a failed
  or replayed handshake does not exist; a reload that re-keys a hinted name
  invalidates it; one address holds many hints; generations bound memory.
- *Budget*: with a fake clock — a flood from one /64 is refused after its burst
  and recovers by refill; **a flood from 10,000 different /64s is stopped by the
  process-wide bucket**; forged PROXY-protocol addresses likewise; a 64 KiB hello
  is refused without a scan once its cost exceeds the burst; loopback peers use
  only the process-wide bucket; a matched scan refunds exactly what it reserved.
- *Shared address*: one client retrying a removed secret plus new legitimate
  users behind the same address — the legitimate users are admitted on the first
  or second attempt (their hints, once written, are exempt).
- *Restart herd*: N legitimate unhinted clients arriving at once are admitted up
  to the bucket, the rest fronted, and the budget recovers as scans complete.
- *Indistinguishability*: a refused hello and a no-match hello produce the same
  bytes to the client (the fronted response), compared end to end.
- *Counters*: each of the six reports moves exactly once per outcome.

**Sabotage checks** (each new test fails when its behaviour is removed): drop the
hint write; drop the hint read; drop the refund; drop the global bucket; key the
global bucket per address; skip the duplicate-key removal; write the hint before
the replay check; swallow a failed verification in the pad path.

**Benchmarks, first commit of the branch, before any optimisation**

- A realistic 517-byte hello builder added next to, not inside,
  `testclient.ClientHello` (`tools/mtgbench` depends on that one; its baselines
  must not move).
- `BenchmarkReadClientHelloMulti` in `fake_test`: N ∈ {1, 10, 100, 1,000, 5,000},
  target first / last / unmatched, hello 517 B and 4 KiB, with allocations. It
  reproduces the 3.9 µs per secret figure in-tree.
- A secrets-count dimension on `BenchmarkDoorHandshake` for `ee-unpaced` (and
  `dd` as the control), target named to sort last or first.
- Runs on the bench box under its rules (`/root/mtg-bench` only, cross-compiled,
  short, cleaned up), before and after, and again after any hot-path change.
  N = 5,000 runs are time-bounded.

**Acceptance**

- A hint hit at N = 5,000 costs within 1.3× of N = 1.
- Precomputed pads stay in the tree only if they cut the unmatched scan's ns per
  candidate by at least 10% on the box (allocations per candidate also reported);
  otherwise they are removed and the report says so.
- A flood test shows zero verifications once the budget is spent, and the
  many-/64s flood is bounded by the process-wide ceiling.
- Existing tests pass untouched; the full gate (pinned `golangci-lint` 2.13.2,
  `go test -count=2 -race ./...`) is green locally. No CI is claimed: GitHub
  Actions is disabled for the account.

## Risks

- **A legitimate unhinted client is fronted during an attack or behind a busy
  address.** Accepted and stated above; mitigated by hints, generous per-address
  numbers and `observe` mode, whose counters let a canary show whether the
  per-address bucket ever refuses legitimate traffic before it is enforced.
- **The nominal block cost is not the real one.** It makes the budget stricter on
  fast CPUs than the stated percentage, never looser than reality on the weakest
  box measured. The numbers are measured and reported.
- **A timing difference between hinted and scanned success** is visible only to
  the authenticated client itself.
- **Hint memory** is bounded (about 32,768 × 2 addresses) and in-process only.

## Not in this piece

Per-address governance, rotation, the doppelganger queue and shaping (B, C, D);
parallel scanning across cores (the same CPU for lower latency — not needed once
the budget bounds the work); a cap on hello size (it would break fronting parity
and post-quantum hellos of about 1.7 KB).

## Decided by the agent (delegated, 2026-10-07)

Audit these; each was a judgement call, not an instruction.

1. The budget is on by default, in `enforce` mode, with the per-address number
   generous and the process-wide bucket as the ceiling.
2. Budget units are nominal milliseconds at 250 ns per block, not a calibrated
   clock.
3. Loopback and unaddressable peers are budgeted only process-wide.
4. 16 hints per address, 32,768 addresses per generation, 30-minute rotation.
5. Hinted verification is exempt from the budget.
6. Precomputed pads are conditional on a measured 10% gain.
7. The new `/stats` object is `faketls_handshake`, and the feature string is
   `handshake-budget`.

## Review

Reviewed before implementation by the advisor (adopted: process-wide ceiling,
shared-address evidence and counters, `observe` mode, benchmark-first ordering,
`testclient.ClientHello` left untouched) and by an independent review pass
recorded in the progress ledger.
