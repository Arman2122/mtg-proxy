# ee handshake at thousands of secrets — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the FakeTLS handshake O(1) for returning clients, cheaper per candidate, and CPU-bounded against floods, with measured before/after numbers.

**Architecture:** `fake` exposes parse and verify primitives; `mtglib` owns policy: a per-address hint cache (try recently matched secrets first) and a two-level work budget in calibrated real CPU (per-address plus process-wide, a 150 ms queue, a scan cap, settle-on-success refunds) that fronts refused unhinted hellos. Benchmarks land first and are measured on the bench box before any optimisation.

**Tech Stack:** Go 1.26.8 (stdlib `crypto/sha256`, `crypto/hmac`, `encoding`), testify, the repo's `entryHarness` end-to-end harness, `go test -bench`/`benchstat`.

**Spec:** `docs/superpowers/specs/2026-10-07-ee-handshake-at-scale-design.md` (revision 2; read it first, this plan does not repeat its reasoning).

## Global Constraints

- Additive only. No release-asset name, API endpoint, existing JSON field, existing config key or `[secrets]`/`[secret-ad-tags]`/`[secret-limits]` change. Default `accept-modes` stays `["ee"]`.
- Not one byte the proxy sends for an accepted hello changes: the golden-byte tests (`mtglib/proxy_golden_faketls_test.go`, the `mtglib/internal/tls/fake` snapshot tests) pass **untouched**. Doppelganger pacing defaults untouched. (Under `enforce`, a hello that would have been accepted can be fronted; a hello above 128 blocks is no longer scanned — both stated in the spec.)
- `/stats`: nothing under `users`. New top-level `faketls_handshake`, omitted until the door has counted something, with `hinted`, `scanned`, `unmatched`, `denied_ip`, `denied_global`, `oversized`, `over_budget_matched` (int64) and `enforced` (bool). New feature string `handshake-budget`; the four hard-coded feature lists in `mtglib/proxy_stats_features_test.go` and the tests enumerating them are edited deliberately.
- Budget (all values from spec §3): `ns/block` calibrated **once per process** (package-level `sync.Once`; minimum of three ~4 ms runs, clamped to 10 ns–2 µs; injectable; logged at start; reported as `ns_per_block` in `/stats`); per-address refill `per-ip-ms` (default 50; **0 disables this bucket**; max 1000) of scan CPU per second, burst 4 s; process-wide refill `cpu-percent` (default 25; 1–100) of `GOMAXPROCS` read once, burst 1 s; both bursts floored at **`4 × candidates × 12` blocks** (depends only on the candidate count, never on the hello's size); a full per-address map (32,768) gives a *new* address no entry (process-wide bucket only) and never resets or rotates on fill (timer rotation only); `cost = candidates × clamp(Blocks, 12, 128)`; `Blocks() > 128` is oversized (never hinted, never scanned, fronted); virtual-schedule `float64` buckets, tokens may go negative to `-rate × 150 ms`; wait ≤ **150 ms** else refuse; both buckets reserved under one lock; reservation single-use, **refunded in full only when the whole handshake succeeds** (after replay check, `attribute` and `admit`), capped at burst; modes `enforce` (default) / `observe` (**identical shadow accounting** — deduct on grant, bucket unchanged on would-refuse, refund on success — but never waits, never refuses; counts the decision and `over_budget_matched`) / `off` (budget and scan cap off). `admit` runs immediately after the door returns (`proxy_serve.go:69-75`), so settlement holds no client round trip.
- Unkeyed peers (loopback, private, link-local, unspecified, no address) use only the process-wide bucket and get no hints. The address key is `limiterKey` (IPv4, or IPv6 /64, `Unmap`ped).
- Hints: up to 16 names per address; at most 32,768 addresses across both generations; **drop-new when full** (never evict); two generations, 30-minute rotation; memory only; `hints` defaults to the value of `track-client-ips` (explicit `true`/`false` overrides); used only when `Blocks() <= 128`; written only after replay check, `attribute` **and `admit`** succeed.
- Block cost of one candidate = `3 + ceil((L+9)/64)` with `L = len(re-synthesised hello record)` (plain-HMAC count, used for the budget whichever path verifies).
- Every new `Proxy` field is nil-safe and acts as "off" when absent (tests build `Proxy{}` literals).
- Address-dependent tests use address-controlled connections (`remoteAddrConn` in `mtglib/proxy_client_ips_test.go`, `connWithAddr` in `mtglib/proxy_accept_addr_test.go`); the default harness peers are loopback and therefore unkeyed.
- Precomputed pads stay only if the box shows ≥ 10% fewer ns per candidate (Task 8 decides).
- Every new test is **sabotage-checked**: break the behaviour, watch the test fail, restore. Record each in the task report.
- Gate before each task's final commit: `go build ./... && go vet ./...` and `go test -count=1 -race` on the packages touched (whole-tree gate is Task 8). Lint with pinned `golangci-lint` 2.13.2: `golangci-lint config verify` THEN `golangci-lint run`; `golangci-lint fmt ./...` after scripted edits.
- LF line endings. Commit messages carry no attribution lines. Never push, tag or merge to `main`.
- Do not change `testclient.ClientHello` behaviour (`tools/mtgbench` baselines depend on it).

## Review Focus

Failure modes the spec implies that no single headline test covers; each has a pinned test in the owning task.

1. **IPv4-mapped and same-/64 peers** share one per-address key. Tasks 5, 6.
2. **Unkeyed peers** (nil, loopback, private): no hint, process-wide bucket only. Tasks 5, 6.
3. **A hello that fails the SNI gate** costs no budget and writes no hint. Task 6.
4. **No hosted secrets**: zero candidates, nothing scanned, front with `frontHost`. Task 4.
5. **A reload between hint write and next hello** (removed, re-keyed, re-sorted name): never a wrong match. Task 5.
6. **A replay of a captured valid hello, a disabled user and an `ip-limit`-refused user** keep their budget charge and write no hint. Tasks 5, 6.
7. **A fragmented 64 KiB hello** is oversized: fronted unscanned, no hint attempts. Task 6.

---

### Task 1: Benchmarks first (no behaviour change)

**Files:**
- Modify: `internal/testclient/faketls.go` (extract the builder, keep `ClientHello` byte-identical)
- Create: `internal/testclient/faketls_padded_test.go`
- Create: `mtglib/internal/tls/fake/verify_bench_test.go` (package `fake_test`)
- Modify: `mtglib/door_bench_test.go` (`BenchmarkDoorHandshake` gains a secrets dimension)

**Interfaces:**
- Produces: `type HelloOptions struct{ PadTo int; At time.Time }` (`PadTo` = length of the single-record form incl. 5-byte header, 0 = none; `At` zero = now); `testclient.ClientHelloWith(key [16]byte, sni string, sessionID []byte, opts HelloOptions) ([]byte, error)`; `testclient.ClientHelloPadded(key, sni, sessionID, size)` = `ClientHelloWith` with `PadTo: size`. The HMAC is over the single-record re-synthesised form; a form above 16,389 bytes is sent as the same handshake message split across TLS records of ≤ 16,384 payload bytes (reader reassembles ≤ 10); bodies up to 65,531 bytes work; impossible sizes error.
- Produces: `BenchmarkReadClientHelloMulti`, `BenchmarkDoorHandshake/<door>/secrets=<N>/<pos>` (names later tasks compare).

- [ ] **Step 1:** In `faketls_padded_test.go` add `TestClientHelloIsUnchangedByTheBuilderSplit`: fixed key, SNI `cover.example.com`, fixed session ID, random bytes `[11:43]` masked, equal to a hex literal captured from the CURRENT code before the refactor (comment says where it came from; never regenerate).
- [ ] **Step 2: Failing tests**: sizes 517, 600, 4096, 16000, 40000, 65540 each accepted by `fake.ReadClientHelloMulti` with the right key (index 0, `MatchedHost == sni`) and rejected (`ErrBadDigest`) with a wrong key; `At = now-10s` rejected with a 3 s skew tolerance and accepted with 30 s; impossible sizes error. Run: FAIL (undefined).
- [ ] **Step 3:** Extract the shared builder in `faketls.go`; implement `ClientHelloWith`, `ClientHelloPadded`; `ClientHello` delegates with zero options. Run the new tests and `go test ./tools/mtgbench/... ./internal/testclient/...`: PASS.
- [ ] **Step 4: `BenchmarkReadClientHelloMulti`** (`fake_test`, own tiny in-memory `net.Conn`): `N ∈ {1,10,100,1000,5000}` × target `first|last|miss` × hello `517|4096` bytes via `ClientHelloPadded`; verifies the outcome (index for first/last, `ErrBadDigest` + `MatchedIndex == -1` for miss); reports `ns/candidate` (ns/op ÷ candidates tried: 1, N, N).
- [ ] **Step 5: Secrets dimension** on `BenchmarkDoorHandshake`, `ee-unpaced` and `dd` only, `secrets=1|100|1000|5000` × `target=first|last`: `N-1` decoys (ee: `GenerateSecret(govCoverHost)`; dd: `GenerateSecretMode(SecretModeDD, "")`) plus the target named `"aaa"`/`"zzz"`; existing sub-benchmarks keep names and behaviour; ee rows send a 517-byte hello through a new helper beside `govEntryCase.openEntry` (other doors' `openEntry` unchanged); `connectThrough` verifies the stream name.
- [ ] **Step 6:** Run both locally once with a short `-benchtime` on small N to prove they run and verify bytes.
- [ ] **Step 7: Commit** `bench: ee handshake by secrets count, with a realistic hello`.

### Task 2: Baseline on the bench box (controller task)

**Files:** Create `benchmarks/results/2026-10-07-handshake-scale-baseline.txt`

- [ ] **Step 1:** Cross-compile the two test binaries locally (`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c`).
- [ ] **Step 2:** Run on the box under its rules (`/root/mtg-bench` only, `ulimit -n 65536`, `TMPDIR=/root/mtg-bench/tmp`, `chmod +x`, TIME_WAIT < 200 between runs, bounded runs, `-count 6` for benchstat; N=5,000 door cells `-benchtime 30x`). Expect the unmatched row at N=1,000 / 517 B to reproduce ~3.9 µs/candidate; record any discrepancy before going on.
- [ ] **Step 3:** Save raw output with a header (load, CPU model, date); clean up; commit `bench: ee handshake baseline on the box`.

### Task 3: `fake` primitives — parse, candidate, verify

**Files:**
- Create: `mtglib/internal/tls/fake/verify.go`
- Modify: `mtglib/internal/tls/fake/client_side.go` (`ReadClientHelloMulti` becomes a wrapper)
- Modify: `mtglib/internal/tls/fake/verify_bench_test.go` (add `BenchmarkVerify` rows `plain` and `pads`, ns per candidate)
- Test: `mtglib/internal/tls/fake/verify_test.go` (package `fake`: the RFC 4231 test drives an unexported `(*Candidate).mac`; may import `internal/testclient`, no cycle)

**Interfaces:**
- Consumes: `testclient.ClientHelloWith`.
- Produces: `type Parsed struct{ Hello *ClientHello; MatchedHost string; … }`; `func ParseClientHelloFor(conn net.Conn, hostnames []string) (*Parsed, error)` (everything `ReadClientHelloMulti` does before its loop, same errors); `func (p *Parsed) Blocks() int` (`3 + ceil((L+9)/64)`); `type Candidate struct{…}`; `func NewCandidate(key []byte) *Candidate` (precomputed pads via `MarshalBinary`; plain when export fails or `len(key) > 64`); `func NewPlainCandidate(key []byte) *Candidate`; `func (p *Parsed) Verify(c *Candidate, skew time.Duration) bool` (same arithmetic, constant-time compare and skew rule; 0 allocations on the pad path using per-`Parsed` scratch digests). `ReadClientHelloMulti` keeps its signature and behaviour (including the `{MatchedIndex: -1, MatchedHost}` + `ErrBadDigest` partial result) as parse + `NewPlainCandidate` + `Verify`.

- [ ] **Step 1: Failing tests**: `TestHMACMatchesRFC4231` (cases 1–4, values **copied from RFC 4231 §4**, via `mac` on pad and plain candidates); `TestVerifyAgreesWithTheReferenceMatcher` (a copy of the pre-change loop as `referenceMatch`; 10,000 seeded scenarios: key at position k of 1–20, wrong key, duplicate keys, fresh and 10 s-skewed timestamps via `HelloOptions.At`, hellos 100 B–64 KiB incl. fragmented; `NewCandidate` and `NewPlainCandidate` both agree); `FuzzParseVerifyAgainstReference` (arbitrary bytes, seeds from the scenarios); `TestPlainFallbackWhenStateCannotBeExported` (test hook forces it) and a 100-byte key; `TestVerifyDoesNotAllocateOnThePrecomputedPath` (`AllocsPerRun` == 0); `TestBlocksCountsTheHMACBlocks` (12 for a 517-byte record; 1,028 for 65,540 bytes; formula in the comment); the existing package tests (snapshot, fragmented, fuzz seeds) still pass; no-match partial result unchanged. Run: FAIL.
- [ ] **Step 2: Implement** per Interfaces; pads: `ipad = key⊕0x36`, `opad = key⊕0x5c`, block-sized, absorbed into two `sha256.New()` and `MarshalBinary`d; `Verify` unmarshals into the per-`Parsed` scratch digests, writes `handshake[:RandomOffset] ‖ zeros(32) ‖ handshake[RandomOffset+RandomLen:]`, finishes inner then outer into a stack `[32]byte`.
- [ ] **Step 3:** Rewrite `ReadClientHelloMulti`; `go test -race ./mtglib/internal/tls/...`: PASS (snapshot/golden untouched).
- [ ] **Step 4: Sabotage**: flip `0x5c`/`0x36`; skip the skew check; compare 27 bytes; return true on `ErrBadDigest`; drop the `len(key) > 64` fallback. Each fails a named test. Restore.
- [ ] **Step 5:** lint; commit `feat(fake): parse and verify a ClientHello as separate steps`.

### Task 4: `secretSet` candidates, and the handshake uses them

**Files:**
- Modify: `mtglib/proxy_secrets.go` (`secretSet`, `buildSecretSet`), `mtglib/proxy_entry.go` (`doFakeTLSHandshake`)
- Test: `mtglib/proxy_secrets_candidates_test.go`

**Interfaces:**
- Consumes: `fake.ParseClientHelloFor`, `fake.NewCandidate`, `(*Parsed).Verify`.
- Produces on `secretSet`: `cands []*fake.Candidate`, `candIdx []int` (index into `secrets`), `candByName map[string]int`. `set.hosted` unchanged.
- Produces: `func (p *Proxy) scanCandidates(parsed *fake.Parsed, set *secretSet, skip func(pos int) bool) (pos int, tried int)` — first matching position in `set.cands`, skipping positions where `skip` is true (nil = none); `-1` if none; `tried` = verifications performed.

- [ ] **Step 1: Failing tests**: `TestCandidatesAreTheHostedSecretsInNameOrder`; `TestLaterDuplicateKeysAreDroppedFromTheCandidates` (two names, one key: one candidate, earlier name wins, as before); `TestCandByNameMapsNamesToPositions`; `TestNoHostedSecretsMeansNoCandidatesAndFronting` (Review Focus 4); `TestFakeTLSAdmitsOnlyHostedSecrets` still passes untouched. Run: FAIL.
- [ ] **Step 2: Implement**; `doFakeTLSHandshake` parses with `ParseClientHelloFor`, scans, maps `candIdx[pos]` where it used `set.hosted[result.MatchedIndex]`; remove the per-handshake `secretKeys`; the failure path fronts with `parsed.MatchedHost` when set, else `set.frontHost`, exactly today's rule.
- [ ] **Step 3:** `go test -race ./mtglib/...`: PASS (golden untouched).
- [ ] **Step 4: Sabotage**: keep duplicates in `cands`; index `secrets` by candidate position. Restore.
- [ ] **Step 5:** lint; commit `feat(mtglib): the ee handshake scans prepared candidates`.

### Task 5: The hint cache

**Files:**
- Create: `mtglib/handshake_hints.go`
- Modify: `mtglib/proxy_entry.go`, `mtglib/proxy_serve.go` (write after `admit`), `mtglib/stream_context.go` (carry what the write needs), `mtglib/proxy.go` (field, construction), `mtglib/proxy_opts.go` (`HandshakeHints *bool`, nil = follow `TrackClientIPs`)
- Test: `mtglib/handshake_hints_test.go`, `mtglib/proxy_entry_hints_test.go`

**Interfaces:**
- Produces: `func hintKey(ip net.IP) (netip.Addr, bool)` (`limiterKey`, and false for loopback, private, link-local, unspecified); `type matchHints struct{…}`; `func newMatchHints(ctx context.Context) *matchHints` (rotation goroutine under the proxy ctx, 30 min; plus `rotate()` for tests); `func (h *matchHints) recall(ip net.IP) []string` (copy, most recent first; nil for unkeyed or nil receiver); `func (h *matchHints) remember(ip net.IP, name string)` (move-to-front, cap 16 names per address, cap 32,768 addresses total, drop-new when full; no-op for unkeyed or nil receiver).
- Produces: `fakeTLSCounters` on `Proxy` (field `fakeStats`, atomics): `hinted`, `scanned`, `unmatched`, `deniedIP`, `deniedGlobal`, `oversized`, `overBudgetMatched`, plus unexported `verifications`.
- Consumes: `secretSet.candByName`, `scanCandidates` + `skip`.

- [ ] **Step 1: Failing unit tests**: order and move-to-front; cap 16 evicts the oldest name; **drop-new when full never evicts an existing address** and a `rotate()` pair frees space; `::ffff:1.2.3.4` and `1.2.3.4` are one key and two hosts in one /64 are one key (Review Focus 1); nil, loopback, `10.x`, `169.254.x`, `::1`, unspecified are unkeyed: `recall` nil, `remember` no-op (Review Focus 2); nil receiver safe.
- [ ] **Step 2: Failing end-to-end tests** (address-controlled conns): `TestAReturningClientIsVerifiedBeforeTheScan` (200 secrets, target sorts last; first connect verifies ~200, second from the same address exactly 1); `TestAStaleHintFallsThroughAndStillMatches`; `TestAHintIsWrittenOnlyAfterAdmit` — a replayed hello, a disabled user, an over-quota user, an `ip-limit`-refused user and a throttled user each leave `recall` empty (Review Focus 6); `TestAReloadNeverMisattributesAHint` (removed name; re-keyed name; re-sorted set — Review Focus 5); `TestSixteenUsersBehindOneAddressAllGetHints`; `TestHintsFollowTrackClientIPsUnlessOverridden` (nil + `TrackClientIPs` false = off, true = on; explicit values win); a large (> 128 blocks) hello never consults hints. Run: FAIL.
- [ ] **Step 3: Implement**; in `doFakeTLSHandshake` after parse/SNI gate: if hints apply (keyed, `Blocks() <= 128`, on), resolve `recall` through `candByName`, verify those first, then `scanCandidates` with `skip` = hinted positions; record the match in the stream context; after `admit` succeeds in `proxy_serve.go`, `remember(ip, secretName)`; counters bumped once per handshake (`hinted`/`scanned`/`unmatched`; `verifications` batched).
- [ ] **Step 4:** `go test -race ./mtglib/...`: PASS.
- [ ] **Step 5: Sabotage**: remove the read; remove the write; write before `admit`; rotate-on-fill instead of drop-new; per-address key for IPv6; hint by index; allow hints for loopback. Each fails a named test. Restore.
- [ ] **Step 6:** lint; commit `feat(mtglib): try the secrets a client address matched before scanning`.

### Task 6: The work budget

**Files:**
- Create: `mtglib/handshake_budget.go`
- Modify: `mtglib/proxy_entry.go`, `mtglib/proxy_serve.go` (settle), `mtglib/stream_context.go`, `mtglib/proxy.go`, `mtglib/proxy_opts.go` (opts, defaults, `valid()`)
- Test: `mtglib/handshake_budget_test.go`, `mtglib/proxy_entry_budget_test.go`

**Interfaces:**
- Produces: `type budgetMode int` (`budgetEnforce` zero value, `budgetObserve`, `budgetOff`); `type scanBudgetConfig struct{ Mode budgetMode; PerIPMillis uint; PerIPDisabled bool; CPUPercent uint; Procs int; NsPerBlock float64; MaxWait time.Duration }` (zero fields = the spec defaults, `MaxWait` 150 ms); `func measureBlockNanos() float64` (minimum of three ~4 ms runs, clamp 10 ns–2 µs) and `func blockNanos() float64` (`sync.Once` around it: one measurement per process, one Info log line naming it); `func newScanBudget(cfg scanBudgetConfig, now func() time.Time) *scanBudget`; `func (b *scanBudget) reserve(ip net.IP, blocks, candidates int) (res *scanReservation, wait time.Duration, v budgetVerdict)` with `budgetVerdict` ∈ {`budgetGranted`, `budgetDeniedIP`, `budgetDeniedGlobal`, `budgetOversized`}; `func (r *scanReservation) settle(success bool)` (single-use: refunds in full, capped at burst, only on `true`; a second call is a no-op); `func (b *scanBudget) enforced() bool`. Nil `*scanBudget` is "off".
- Produces on `ProxyOpts`: `HandshakeBudgetMode string` (`""`/`"enforce"`/`"observe"`/`"off"`; else `valid()` fails), `HandshakeBudgetPerIPMillis *uint` (nil = 50; 0 = per-address bucket disabled; > 1000 fails `valid()`), `HandshakeBudgetCPUPercent uint` (0 = 25; > 100 fails `valid()`).
- Consumes: `(*Parsed).Blocks()`, `scanCandidates`, `hintKey`, `fakeStats`, the proxy ctx for the wait.

- [ ] **Step 1: Failing unit tests** (fake clock, injected `NsPerBlock`): `TestPerAddressBurstThenRefill`; **`TestManyAddressesAreStoppedByTheProcessWideBucket`** (10,000 distinct /64s) and `TestForgedAddressesDoNotEscapeTheCeiling`; `TestTheQueueAdmitsASmallHerdAndRefusesPastTheWait` (150 ms); `TestACostAboveWhatTheWaitAllowsIsRefused`; `TestChargeIsRefundedExactlyOnceAndOnlyOnSuccess` (settle(true) twice refunds once; settle(false) keeps); `TestBurstFloorIsFourTimesCandidatesTimesTwelve` (the formula verbatim; a flood of 128-block hellos does not raise the cap; large N never permanently starves); `TestAFullAddressMapGivesNewAddressesNoEntryAndNeverResets` (32,768 forged addresses: an already-draining address keeps its drained bucket; a new one is held to the process-wide bucket only); `TestAdmissionIsSizeUniform` (100-byte and 517-byte hellos cost the same; a 4 KiB hello costs more); `TestOversizedIsRefusedWithoutScanning` (Blocks 129; and a 64 KiB fragmented hello — Review Focus 7); `TestUnkeyedPeersUseOnlyTheProcessWideBucket` (Review Focus 2); `TestMappedAndSameSlash64PeersShareOneAddressBucket` (Review Focus 1); `TestPerIPZeroDisablesOnlyTheAddressBucket`; `TestObserveShadowAccountingDrainsLikeEnforce` (same sequence of reserves/settles gives the same would-refuse decisions in observe as refusals in enforce; observe never waits nor refuses) and its end-to-end twin `TestObserveReportsOverBudgetMatchedDuringAFlood` (flood in observe mode, then a legitimate hello during it moves `over_budget_matched` and `denied_*`, and the hello is served); `TestOffNeverRefusesNorCapsSize`; `TestCalibrationRunsOncePerProcess`; `TestBucketsStayWithinTheirBounds` (never below the debt floor or above burst; no overflow after a 24 h idle); `TestCalibrationIsClamped` (an injected pathological timer gives 10 ns / 2 µs bounds).
- [ ] **Step 2: Failing end-to-end tests** (address-controlled conns, small injected `MaxWait`): `TestARefusedHelloIsFrontedLikeANoMatch` (the cover site receives byte-identical bytes for a refused and a wrong-key hello; `deniedGlobal` moves exactly once; no verification for the refused one); `TestAReplayedValidHelloKeepsItsCharge` and `TestADeniedUserKeepsItsCharge` and `TestAnIPLimitRefusedUserKeepsItsCharge` (Review Focus 6); `TestSharedAddressStaleSecretDoesNotLockOutNewUsers` (one client retries a removed secret until its address bucket is drained; new users behind the address with a hint are admitted; without a hint, admitted on a first or second attempt after the wait — assert the real outcome); `TestAHelloThatFailsTheSNIGateCostsNoBudget` (Review Focus 3); `TestHintedClientsAreExemptFromTheBudget`; `TestEveryOutcomeMovesExactlyOneCounter` (the spec §5 table, **enforce mode only**; observe mode's would-refuse counters are asserted as pairs with `scanned`/`unmatched` in the observe tests above). Run: FAIL.
- [ ] **Step 3: Implement** `handshake_budget.go` (two-generation per-address map shaped like `obfuscatedLimiter`, same drop/promote care, a single mutex over map and the global bucket); wire between the hint attempt and the scan per spec §4: reserve, wait on the stream/proxy context, scan, store the reservation on the stream context, `settle(true)` after `admit` succeeds in `proxy_serve.go` (any earlier exit settles `false`); refusal fronts through the no-match call; observe mode counts and scans without reserving. `NewProxy` calibrates once and builds the budget with the real clock; add the three opts and `valid()` checks.
- [ ] **Step 4:** `go test -race ./mtglib/...`: PASS.
- [ ] **Step 5: Sabotage**: refund on match (before the replay check); drop the refund entirely; drop the process-wide bucket; make it per-address; drop the oversized cap; drop the cost floor; make refusal `Close()`; drop the burst floor; skip the wait. Each fails a named test. Restore.
- [ ] **Step 6:** lint; commit `feat(mtglib): a CPU budget for ee hellos that match nothing`.

### Task 7: Config, `/stats`, feature string, docs

**Files:**
- Modify: `internal/config/parse.go`, `internal/config/config.go` (+ `type_handshake_budget_mode.go` following `type_doppel_shaping.go`), `internal/cli/run_proxy.go`
- Modify: `mtglib/proxy_stats.go`, `mtglib/proxy_api.go`, `mtglib/proxy_stats_features_test.go`
- Modify: `example.config.toml`, `docs/wiki/Configuration.md`, `docs/wiki/Security.md` (incl. the fronting-indistinguishability list), `docs/wiki/Monitoring.md`, `docs/wiki/Multi-User-and-API.md` (feature list and table), `README.md` (`/stats` sample)
- Test: `internal/config/handshake_budget_test.go`, `mtglib/proxy_stats_handshake_test.go`

**Interfaces:**
- Produces: `[defense.handshake-budget]` with `mode`, `per-ip-ms`, `cpu-percent`, `hints` (`hints` and `per-ip-ms` as pointers in `parse.go` so an explicit `false`/`0` survives: unset = follow `track-client-ips` / 50); `Config.Defense.HandshakeBudget`; validation rejects a mode outside the three, `per-ip-ms` > 1000, `cpu-percent` outside 1–100; `run_proxy.go` maps them into `ProxyOpts`.
- Produces: `FakeTLSJSON{Hinted, Scanned, Unmatched, DeniedIP, DeniedGlobal, Oversized, OverBudgetMatched int64; Enforced bool; NsPerBlock float64}` (json `hinted`, `scanned`, `unmatched`, `denied_ip`, `denied_global`, `oversized`, `over_budget_matched`, `enforced`, `ns_per_block`), `StatsResponse.FakeTLSHandshake *FakeTLSJSON` json `faketls_handshake,omitempty`, set in `handleStats` only when any counter is non-zero; `FeatureHandshakeBudget = "handshake-budget"` between `FeatureFakeTLS` and `FeatureIPLimits` in `supportedFeatures`.

- [ ] **Step 1: Failing tests**: config — an absent table keeps today's behaviour; each mode parses; invalid values fail naming the key; explicit `hints = false` and `per-ip-ms = 0` survive into `ProxyOpts`; `unknownKeys` does not list the new keys; `TestPanelEmittedConfigIsAccepted` (`internal/config/panel_contract_test.go`) untouched and green. Stats — `faketls_handshake` absent on a fresh proxy (`TestStatsResponseShapeUnchanged` and the raw-shape tests untouched and green), present with distinct counts per field (a transposed mapping fails), `enforced` reflects the mode; the four literal feature lists and the name test in `proxy_stats_features_test.go` gain `handshake-budget` and the `IsSorted` assertion passes. Run: FAIL.
- [ ] **Step 2: Implement** config, wiring, stats object, feature.
- [ ] **Step 3: Docs** as listed: the three-and-one keys with defaults, the accepted-degradation paragraph, the restart-only note, the privacy note for hints, the timing statement, how to use `observe` and `over_budget_matched` for a canary.
- [ ] **Step 4:** `go test -race ./internal/... ./mtglib/...`: PASS.
- [ ] **Step 5: Sabotage**: transpose two JSON fields; emit the object when empty; drop the feature string; insert it unsorted; let `hints = false` read as unset. Each fails. Restore.
- [ ] **Step 6:** lint (`config verify` then `run`); commit `feat: [defense.handshake-budget], faketls_handshake stats and the handshake-budget feature`.

### Task 8: Gate, box measurement, the pads decision, report (controller task)

**Files:** Create `benchmarks/results/2026-10-07-handshake-scale-after.txt`, `benchmarks/results/2026-10-07-handshake-scale-report.md`; modify `mtglib/internal/tls/fake/verify.go` and tests only if pads fail the rule.

- [ ] **Step 1: Full gate**: `golangci-lint config verify` then `run`; `go build ./... && go vet ./...`; `go test -count=2 -race ./...`; `govulncheck ./...` if available; golden/snapshot untouched (`git diff origin/main -- '*golden*' '*testdata*'` empty).
- [ ] **Step 2: Box run after**, Task 2's protocol and cells, plus `BenchmarkVerify` pads vs plain, plus the calibrated `ns/block` the proxy reports on the box (compare with the 325 ns estimate). Apply the rule: pads stay only if ≥ 10% fewer ns/candidate on the unmatched scan at N=1,000 / 517 B; otherwise `NewCandidate` returns the plain candidate, delete the pad path and tests, re-run, say so in the report.
- [ ] **Step 3: Report**: `benchstat` tables (baseline vs after), the acceptance checks (hint hit at N=5,000 within 1.3× of N=1; flood tests; many-/64s ceiling), a hint-hit-rate reading from a replayed multi-user scenario, honest limits (2 vCPU, loopback), the sabotage log.
- [ ] **Step 4:** whole-branch independent review (fresh reviewer, most capable model); fix findings test-first; re-run the gate; commit `bench: ee handshake at scale, before and after`.
