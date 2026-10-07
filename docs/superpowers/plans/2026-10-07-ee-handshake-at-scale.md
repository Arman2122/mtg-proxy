# ee handshake at thousands of secrets — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the FakeTLS handshake O(1) for returning clients, cheaper per candidate, and CPU-bounded against floods, with measured before/after numbers.

**Architecture:** `fake` exposes parse and verify primitives; `mtglib` owns policy: a per-address hint cache (try recently matched secrets first) and a two-level work budget (per-address plus process-wide, in SHA-256 blocks, reserve-then-refund) that fronts refused unhinted hellos. Benchmarks land first and are measured on the bench box before any optimisation.

**Tech Stack:** Go 1.26.8 (stdlib `crypto/sha256`, `crypto/hmac`, `encoding`), testify, the repo's `entryHarness` end-to-end test harness, `go test -bench`/`benchstat`.

**Spec:** `docs/superpowers/specs/2026-10-07-ee-handshake-at-scale-design.md` (read it first; this plan does not repeat its reasoning).

## Global Constraints

- Additive only. No release-asset name, API endpoint, existing JSON field, existing config key or `[secrets]`/`[secret-ad-tags]`/`[secret-limits]` change. Default `accept-modes` stays `["ee"]`.
- No wire change: the golden-byte tests (`mtglib/proxy_golden_faketls_test.go`, `mtglib/internal/tls/fake` snapshot tests) pass **untouched**. Doppelganger pacing defaults untouched.
- `/stats`: nothing added under `users` (the panel bills every `users` key as a client). New data is a top-level `faketls_handshake` object, omitted until the door has counted something. New feature string `handshake-budget` (the four hard-coded feature lists in `mtglib/proxy_stats_features_test.go` are edited deliberately).
- Budget numbers: nominal 250 ns per SHA-256 block; per-address refill `per-ip-ms` (default 50) ms/s = 200,000 blocks/s, burst 4 s; process-wide refill `cpu-percent` (default 25) % of `GOMAXPROCS` = 1,000,000 blocks/s per core, burst 1 s; hinted verification exempt; a matched scan refunds its whole reservation; refusal fronts, never closes; loopback and unaddressable peers use only the process-wide bucket; modes `enforce` (default), `observe`, `off`.
- Hints: up to 16 names per address, 32,768 addresses per generation, two generations, 30-minute rotation, memory only, written only after replay check and `attribute` succeed.
- Block cost of one candidate = `3 + ceil((len(handshakeBytes)+9)/64)` (the plain-HMAC count, used for the budget regardless of path).
- Precomputed pads stay only if the box shows ≥ 10% fewer ns per candidate on the unmatched scan (Task 8 decides).
- Every new test is **sabotage-checked**: break the behaviour, watch the test fail, restore. Record each in the task report.
- Gate before each task's final commit: `go build ./... && go vet ./...` and `go test -count=1 -race ./mtglib/... ./internal/...` for the packages touched (the whole-tree gate is Task 8). Lint with the pinned `golangci-lint` 2.13.2: `golangci-lint config verify` THEN `golangci-lint run`; `golangci-lint fmt ./...` after scripted edits.
- Write files with LF line endings. Commit messages carry no attribution lines. Never push, tag or merge to `main`.
- Do not modify `testclient.ClientHello` behaviour (`tools/mtgbench` baselines depend on it).

## Review Focus

Failure modes the spec implies that no single task's headline test covers; each has a pinned test in the owning task.

1. **IPv4-mapped and IPv6 same-/64 peers** must share one per-address key (`::ffff:1.2.3.4` = `1.2.3.4`; two hosts in one /64 share a bucket and a hint set). Task 5 (hints) and Task 6 (budget).
2. **`ctx.ClientIP()` nil** (a `net.Pipe`, a non-TCP conn): no per-address key, process-wide bucket only, hints silently off. Tasks 5, 6.
3. **A hello that fails the SNI gate** costs no budget and writes no hint (it never reaches the scan). Task 6.
4. **No hosted secrets at all**: zero candidates, nothing scanned, front with `frontHost`. Task 4.
5. **A reload between the hint write and the next hello** (name removed, name re-keyed, name re-sorted): the hint must fail verification or be skipped, never match a different user. Task 5.

---

### Task 1: Benchmarks first (no behaviour change)

**Files:**
- Modify: `internal/testclient/faketls.go` (extract the builder, keep `ClientHello` byte-identical)
- Create: `internal/testclient/faketls_padded_test.go`
- Create: `mtglib/internal/tls/fake/verify_bench_test.go` (package `fake_test`)
- Modify: `mtglib/door_bench_test.go` (`BenchmarkDoorHandshake` gains a secrets dimension)

**Interfaces:**
- Produces: `testclient.ClientHelloPadded(key [16]byte, sni string, sessionID []byte, size int) ([]byte, error)` — a ClientHello whose whole TLS record (5-byte header included) is exactly `size` bytes, via a TLS padding extension (type `0x0015`) appended after the SNI extension; `size` below the unpadded length, or above 65,535, is an error. Used by every later benchmark and test that needs a realistic (517-byte) or large hello.
- Produces: `BenchmarkReadClientHelloMulti` and `BenchmarkDoorHandshake/<door>/secrets=<N>/<pos>` (names later tasks compare before/after).

- [ ] **Step 1: Pin `ClientHello` before touching it.** In `faketls_padded_test.go` add `TestClientHelloIsUnchangedByTheBuilderSplit`: build with a fixed key, SNI `cover.example.com` and session ID, mask bytes `[11:43]` (the random) and assert equality with a hex literal captured **from the current code** (run once, paste the output; the test comment says where it came from and that it must never be regenerated).
- [ ] **Step 2: Failing tests for `ClientHelloPadded`**: `TestClientHelloPaddedHasTheRequestedSize` (sizes 517, 600, 4096, 16000 produce `len == size`), `TestClientHelloPaddedIsStillAValidHello` (feed it to `fake.ReadClientHelloMulti` with the same key: matches index 0, `MatchedHost == sni`), `TestClientHelloPaddedRefusesAnImpossibleSize` (size 10 and 70000 error). Run: FAIL (undefined).
- [ ] **Step 3: Extract `clientHello(key, sni, sessionID, padTo int)` in `faketls.go`**; `ClientHello` calls it with `padTo = 0` and its bytes stay identical; `ClientHelloPadded` calls it with `size`. Run Task 1's tests: PASS; run `go test ./tools/mtgbench/... ./internal/testclient/...`: PASS.
- [ ] **Step 4: `BenchmarkReadClientHelloMulti`** (package `fake_test`, may import `internal/testclient`): sub-benchmarks `plain|…` for the existing function with `N ∈ {1,10,100,1000,5000}` secrets × target position `first|last|miss` × hello size `517|4096`; secrets are random 16-byte keys; the target key is at the chosen index (`miss` = a key not in the list); the hello is `testclient.ClientHelloPadded`; each iteration reads the hello through a fresh in-memory `net.Conn` (reuse the `connMock`/`parseClientHelloConnMock` style already in this package's tests) and the benchmark reports `ns/candidate` (= ns/op ÷ candidates tried) and allocs. Time per iteration at N=5000 is ~20 ms: keep `-benchtime` short in the documented command, not in the code.
- [ ] **Step 5: Secrets dimension on `BenchmarkDoorHandshake`.** For `ee-unpaced` and `dd` only, add sub-benchmarks `secrets=1|100|1000|5000` × `target=first|last`: `N-1` decoys from `GenerateSecret(govCoverHost)` (dd decoys from `GenerateSecretMode(SecretModeDD, "")`) plus the target, named `"aaa"` (first) or `"zzz"` (last) so `buildSecretSet`'s name sort puts it where the name says. The existing single-secret sub-benchmarks keep their names and behaviour. For the ee rows the hello is `ClientHelloPadded(…, 517)`: add a `govEntryCase`-level helper rather than editing `openEntry` for the other doors.
- [ ] **Step 6: Run both benchmarks locally once** (`go test -run '^$' -bench 'ReadClientHelloMulti/.*N=100' -benchtime 50x ./mtglib/internal/tls/fake` and `-bench 'DoorHandshake/ee-unpaced/secrets=100' -benchtime 20x ./mtglib`) to prove they run and verify bytes (a wrong target must fail the benchmark, not silently time a miss).
- [ ] **Step 7: Commit** `bench: ee handshake by secrets count, with a realistic hello`.

### Task 2: Baseline on the bench box (controller task)

**Files:**
- Create: `benchmarks/results/2026-10-07-handshake-scale-baseline.txt`

- [ ] **Step 1:** Cross-compile the two test binaries locally (`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o <scratch>/fake.test ./mtglib/internal/tls/fake` and `… -o <scratch>/mtglib.test ./mtglib`).
- [ ] **Step 2:** Run on the box under its rules: work only in `/root/mtg-bench`, `ulimit -n 65536`, `TMPDIR=/root/mtg-bench/tmp`, `chmod +x`, wait for `ss -Htan state time-wait | wc -l` < 200 between runs, runs bounded (`-benchtime` ~ 2 s per cell; N=5,000 door cells `-benchtime 30x`), `-count 6` for benchstat. Expect the unmatched-scan row at N=1,000/517 B to reproduce ~3.9 µs/candidate; if it does not, record the discrepancy before going on.
- [ ] **Step 3:** Save raw output and a short header (box load average, `lscpu` model, date) to the results file; clean up `/root/mtg-bench`. Commit `bench: ee handshake baseline on the box`.

### Task 3: `fake` primitives — parse, candidate, verify

**Files:**
- Create: `mtglib/internal/tls/fake/verify.go`
- Modify: `mtglib/internal/tls/fake/client_side.go` (`ReadClientHelloMulti` becomes a wrapper)
- Modify: `mtglib/internal/tls/fake/verify_bench_test.go` (add `BenchmarkVerify` rows `plain` and `pads`, ns per candidate, so Task 8's A/B needs no new code)
- Test: `mtglib/internal/tls/fake/verify_test.go` (in package `fake`, not `fake_test`: the RFC 4231 test drives an unexported `(*Candidate).mac` over arbitrary data)

**Interfaces:**
- Produces:
  - `type Parsed struct { Hello *ClientHello; MatchedHost string; /* unexported: re-synthesised bytes, scratch hashes */ }`
  - `func ParseClientHelloFor(conn net.Conn, hostnames []string) (*Parsed, error)` — everything `ReadClientHelloMulti` does before its loop (parse, SNI gate), returning the same errors; on the SNI-gate failure it returns the `nil, err` it returns today.
  - `func (p *Parsed) Blocks() int` — `3 + ceil((len(handshakeBytes)+9)/64)`.
  - `type Candidate struct{ … }`, `func NewCandidate(key []byte) *Candidate` (precomputed inner/outer states via `MarshalBinary`; silently plain when the hash cannot export), `func NewPlainCandidate(key []byte) *Candidate` (always `hmac.New`).
  - `func (p *Parsed) Verify(c *Candidate, skew time.Duration) bool` — same arithmetic, constant-time compare and skew rule as the old loop body; zero allocations on the precomputed path.
  - `ReadClientHelloMulti` unchanged in signature and behaviour (including the partial result `{MatchedIndex: -1, MatchedHost}` + `ErrBadDigest`), implemented as parse + `NewPlainCandidate` + `Verify` in order.

- [ ] **Step 1: Failing tests** (`verify_test.go`):
  - `TestHMACMatchesRFC4231`: the published HMAC-SHA256 test cases 1–4 (keys, data and expected MACs **copied from RFC 4231 section 4**, with a comment saying so) computed through an exported-for-test hook of the pad path and through the plain path; both equal the RFC value.
  - `TestVerifyAgreesWithTheReferenceMatcher`: a copy of the pre-change `ReadClientHelloMulti` loop lives in this test file as `referenceMatch`; over 10,000 seeded scenarios (key at position k of 1–20 secrets, wrong key, duplicate keys, fresh and 10 s-skewed timestamps, hello sizes 100 B–4 KiB via `testclient.ClientHelloPadded`) `Verify` over `NewCandidate` and over `NewPlainCandidate` both agree with `referenceMatch` on every scenario.
  - `TestPlainFallbackWhenStateCannotBeExported`: build a `Candidate` forced into fallback (test hook) and assert it still verifies the right key and rejects a wrong one.
  - `TestVerifyDoesNotAllocateOnThePrecomputedPath`: `testing.AllocsPerRun` over 100 `Verify` calls == 0.
  - `TestBlocksCountsTheHMACBlocks`: `Blocks()` is 12 for a 517-byte record and 1,028 for 65,531 bytes (derive each by the formula in the test comment: `3 + ceil((L+9)/64)`).
  - `TestReadClientHelloMultiBehaviourIsUnchanged`: the existing package tests (snapshot, fragmented, fuzz seeds) still pass — assert by running them; add one case that the no-match partial result is still returned.
  Run: FAIL (undefined).
- [ ] **Step 2: Implement** `verify.go` per the Interfaces block; pad precompute: `ipad = key⊕0x36`, `opad = key⊕0x5c` padded to the 64-byte block (a key longer than 64 bytes is hashed first, per RFC 2104), absorb into two `sha256.New()` digests, `MarshalBinary` each; `Verify` unmarshals into two per-`Parsed` scratch digests, writes `handshake[:RandomOffset] ‖ zeros(32) ‖ handshake[RandomOffset+RandomLen:]`, finishes inner then outer into a stack `[32]byte`.
- [ ] **Step 3:** Rewrite `ReadClientHelloMulti` as the wrapper; run the whole `fake` package, `go test -race ./mtglib/internal/tls/...`: PASS (golden/snapshot untouched).
- [ ] **Step 4: Sabotage**: flip `0x5c`/`0x36`; skip the timestamp-skew check; compare 27 bytes instead of 28; return true on `ErrBadDigest`; each must fail a named test above. Restore.
- [ ] **Step 5:** `golangci-lint` clean; commit `feat(fake): parse and verify a ClientHello as separate steps`.

### Task 4: `secretSet` candidates, and the handshake uses them

**Files:**
- Modify: `mtglib/proxy_secrets.go` (`secretSet`, `buildSecretSet`)
- Modify: `mtglib/proxy_entry.go` (`doFakeTLSHandshake`)
- Test: `mtglib/proxy_secrets_candidates_test.go`

**Interfaces:**
- Consumes: `fake.ParseClientHelloFor`, `fake.NewCandidate`, `(*Parsed).Verify`.
- Produces on `secretSet`: `cands []*fake.Candidate`, `candIdx []int` (`candIdx[i]` indexes `secrets`), `candByName map[string]int` (name → position in `cands`). `set.hosted` stays as it is.
- Produces: `func (p *Proxy) scanCandidates(parsed *fake.Parsed, set *secretSet, skip func(pos int) bool) (pos int, tried int)` — verifies `set.cands` in order, skipping positions `skip` names (nil = none), returns the first matching position or `-1`, and how many it verified.

- [ ] **Step 1: Failing tests**: `TestCandidatesAreTheHostedSecretsInNameOrder`; `TestLaterDuplicateKeysAreDroppedFromTheCandidates` (two names, one key: one candidate, `candIdx` points at the earlier name; a handshake with that key attributes the earlier name — the same as before this change); `TestCandByNameMapsNamesToPositions`; `TestNoHostedSecretsMeansNoCandidatesAndFronting` (Review Focus 4: an `entryHarness` with only a dd secret, an ee hello is fronted with `frontHost`); `TestFakeTLSAdmitsOnlyHostedSecrets` still passes untouched. Run: FAIL.
- [ ] **Step 2: Implement** the fields in `buildSecretSet` and `scanCandidates`; `doFakeTLSHandshake` parses with `ParseClientHelloFor`, scans, and maps `candIdx[pos]` where it used `set.hosted[result.MatchedIndex]`; remove the per-handshake `secretKeys` slice. Failure path: front with `parsed.MatchedHost` when set, else `set.frontHost` — exactly today's rule.
- [ ] **Step 3:** `go test -race ./mtglib/...`: PASS (includes golden FakeTLS tests, untouched).
- [ ] **Step 4: Sabotage**: keep duplicates in `cands` (the duplicate test must fail); index `secrets` with the candidate position (attribution tests fail). Restore.
- [ ] **Step 5:** lint; commit `feat(mtglib): the ee handshake scans prepared candidates`.

### Task 5: The hint cache

**Files:**
- Create: `mtglib/handshake_hints.go`
- Modify: `mtglib/proxy_entry.go`, `mtglib/proxy.go` (field + construction)
- Test: `mtglib/handshake_hints_test.go`, `mtglib/proxy_entry_hints_test.go`

**Interfaces:**
- Produces: `type matchHints struct{…}`; `func newMatchHints(ctx context.Context) *matchHints` (rotation goroutine under the proxy ctx, 30 min, like `obfuscatedLimiter`; plus `rotate()` for tests); `func (h *matchHints) recall(ip net.IP) []string` (names, most recent first, copy; nil for no address); `func (h *matchHints) remember(ip net.IP, name string)` (move-to-front, cap 16, cap 32,768 addresses/generation, keys via `limiterKey`).
- Produces counters on a new `fakeTLSCounters` struct on `Proxy` (field `fakeStats`, atomics): `hinted`, `scanned`, `unmatched`, `deniedIP`, `deniedGlobal`, plus unexported `verifications` (total `Verify` calls, added once per handshake).
- Consumes: `secretSet.candByName`, `scanCandidates` with its `skip`.

- [ ] **Step 1: Failing unit tests** (`handshake_hints_test.go`): remember/recall order and move-to-front; cap 16 evicts the oldest; two generations (a rotate keeps recent, a second rotate drops); `::ffff:1.2.3.4` and `1.2.3.4` are one address and two hosts in one /64 are one address (Review Focus 1); nil IP: `recall` returns nil, `remember` is a no-op (Review Focus 2); address cap evicts via rotation.
- [ ] **Step 2: Failing end-to-end tests** (`proxy_entry_hints_test.go`, `entryHarness`, address-controlled conns as `proxy_client_ips_test.go` does): `TestAReturningClientIsVerifiedBeforeTheScan` (set of 200 secrets, target sorts last; first connect verifies ~200, second from the same address verifies exactly 1 — assert on `verifications`); `TestAStaleHintFallsThroughAndStillMatches` (hint names user X, the hello is user Y's: still matches, hinted miss counted as `scanned`); `TestAHintIsWrittenOnlyAfterTheWholeSuccessPath` (a replayed hello, a hello of a disabled user (denied by `attribute`) and a no-match hello each leave `recall` empty); `TestAReloadInvalidatesAHint` (Review Focus 5: remove the hinted name; re-key it; both ⇒ no wrong attribution, handshake still correct); `TestAddressesSharingOneIPAllGetHints` (16 distinct users from one address; all are verified first on a later connect). Run: FAIL.
- [ ] **Step 3: Implement** `handshake_hints.go`; in `doFakeTLSHandshake`: after the parse, `names := hints.recall(ctx.ClientIP())`, resolve through `candByName`, verify those first; on a miss `scanCandidates` with `skip` = the hinted positions; after `attribute` succeeds call `remember(ip, set.names[idx])`; bump `hinted`/`scanned`/`unmatched`/`verifications` once each per handshake. `NewProxy` constructs `matchHints` next to `obfsLimiter`.
- [ ] **Step 4:** `go test -race ./mtglib/...`: PASS.
- [ ] **Step 5: Sabotage**: remove the hint read; remove the write; write before the replay check; use an index instead of a name; make `limiterKey` per-address for IPv6. Each fails a named test. Restore.
- [ ] **Step 6:** lint; commit `feat(mtglib): try the secrets a client address matched before scanning`.

### Task 6: The work budget

**Files:**
- Create: `mtglib/handshake_budget.go`
- Modify: `mtglib/proxy_entry.go`, `mtglib/proxy.go`, `mtglib/proxy_opts.go` (opts + defaults + validation)
- Test: `mtglib/handshake_budget_test.go`, `mtglib/proxy_entry_budget_test.go`

**Interfaces:**
- Produces: `type budgetMode int` (`budgetEnforce` zero value, `budgetObserve`, `budgetOff`); `type scanBudgetConfig struct{ Mode budgetMode; PerIPMillis, CPUPercent uint; Procs int }` (zero fields mean the spec defaults 50 ms, 25 %, `runtime.GOMAXPROCS(0)`); `func newScanBudget(ctx context.Context, cfg scanBudgetConfig, now func() time.Time) *scanBudget`; `func (b *scanBudget) reserve(ip net.IP, cost int64) (scanReservation, budgetVerdict)` with `budgetVerdict` ∈ {`budgetGranted`, `budgetDeniedIP`, `budgetDeniedGlobal`}; `func (b *scanBudget) refund(r scanReservation)`; `func (b *scanBudget) enforced() bool` (true in `enforce` mode; Task 7's `/stats` reads it).
- Produces on `ProxyOpts`: `HandshakeBudgetMode string` (`""`→enforce, `"enforce"`, `"observe"`, `"off"`; anything else fails `valid()`), `HandshakeBudgetPerIPMillis uint` (0→50; >1000 fails `valid()`), `HandshakeBudgetCPUPercent uint` (0→25; >100 fails `valid()`).
- Consumes: `(*Parsed).Blocks()`, `scanCandidates`, `limiterKey`, `fakeStats`.

- [ ] **Step 1: Failing unit tests** (fake clock injected via `now`): `TestPerAddressBurstThenRefill` (200,000 blocks/s, burst 800,000; a /64 flood is refused after its burst and admitted again after refill); **`TestManyAddressesAreStoppedByTheProcessWideBucket`** (10,000 distinct /64s each within their own burst are refused once the process-wide bucket — 1,000,000 blocks/s × `Procs`, burst 1 s — is spent); `TestForgedAddressesDoNotEscapeTheCeiling` (same, addresses randomised per call); `TestACostAboveTheBurstIsRefusedWithoutAScan` (a 64 KiB hello at 5,000 secrets); `TestAMatchedScanRefundsExactlyItsReservation` and `TestAFailedScanKeepsItsCharge`; `TestLoopbackAndNilUseOnlyTheProcessWideBucket` (Review Focus 2); `TestMappedAndSameSlash64PeersShareOneAddressBucket` (Review Focus 1: `::ffff:1.2.3.4` drains `1.2.3.4`'s bucket; two hosts in one /64 drain one bucket; a different /64 is unaffected); `TestObserveModeCountsButNeverRefuses`; `TestOffModeNeverRefuses`; `TestBucketsNeverGoNegativeOrExceedBurst`; the nominal constants (`4000 blocks per ms`, defaults) pinned as named test values.
- [ ] **Step 2: Failing end-to-end tests** (`proxy_entry_budget_test.go`): `TestARefusedHelloIsFrontedLikeANoMatch` (a harness with a tiny process-wide bucket; the refused hello and a wrong-key hello yield **byte-identical** client-visible responses from the fake cover site, and `deniedGlobal` moves exactly once; no verification happened for the refused one); `TestSharedAddressStaleSecretDoesNotLockOutNewUsers` (spec "Shared address": one client retries a removed secret until its address bucket is drained; new legitimate users from the same address with a hint are admitted; users without a hint are fronted on the first attempt and admitted on a later one after refill — assert the actual first/second attempt outcome); `TestARestartHerdIsAdmittedUpToTheBucketAndRecovers`; `TestAHelloThatFailsTheSNIGateCostsNoBudget` (Review Focus 3); `TestHintedClientsAreExemptFromTheBudget`. Run: FAIL.
- [ ] **Step 3: Implement** `handshake_budget.go` (two-generation per-address map shaped like `obfuscatedLimiter`; one process-wide bucket; reserve takes from both or neither; reject when cost > either burst); wire into `doFakeTLSHandshake` between the hint attempt and the scan: reserve cost = `uint(remaining candidates) × Blocks()`; refused (enforce) ⇒ count, front with the SNI host through the existing no-match call, return false; observe ⇒ count, scan anyway; after the scan, refund on match. Add the three `ProxyOpts` fields and `valid()` checks; `NewProxy` builds the budget with the real clock.
- [ ] **Step 4:** `go test -race ./mtglib/...`: PASS.
- [ ] **Step 5: Sabotage**: drop the refund; drop the process-wide bucket; make the process-wide bucket per-address; skip the cost>burst rule; make a refused hello `Close()` instead of fronting (the byte-identical test fails); reserve from only one bucket. Each fails a named test. Restore.
- [ ] **Step 6:** lint; commit `feat(mtglib): a CPU budget for ee hellos that match nothing`.

### Task 7: Config, `/stats`, feature string, docs

**Files:**
- Modify: `internal/config/parse.go`, `internal/config/config.go` (+ `type_handshake_budget_mode.go` following `type_doppel_shaping.go`), `internal/cli/run_proxy.go`
- Modify: `mtglib/proxy_stats.go`, `mtglib/proxy_api.go`, `mtglib/proxy_stats_features_test.go`
- Modify: `example.config.toml`, `docs/wiki/Configuration.md`, `docs/wiki/Security.md`, `docs/wiki/Monitoring.md`
- Test: `internal/config/handshake_budget_test.go`, `mtglib/proxy_stats_handshake_test.go`

**Interfaces:**
- Produces: `[defense.handshake-budget]` with `mode`, `per-ip-ms`, `cpu-percent` (parse types and `config.Config.Defense.HandshakeBudget`); `Config` validation rejects a mode outside the three, `per-ip-ms` outside 1–1000, `cpu-percent` outside 1–100; `run_proxy.go` passes them into `ProxyOpts`.
- Produces: `FakeTLSJSON{Hinted, Scanned, Unmatched, DeniedIP, DeniedGlobal int64; Enforced bool}` (json `hinted`, `scanned`, `unmatched`, `denied_ip`, `denied_global`, `enforced`), `StatsResponse.FakeTLSHandshake *FakeTLSJSON` json `faketls_handshake,omitempty`, set in `handleStats` only when any counter is non-zero; `FeatureHandshakeBudget = "handshake-budget"`, inserted in sorted position in `supportedFeatures` (between `FeatureFakeTLS` and `FeatureIPLimits`).

- [ ] **Step 1: Failing tests**: config — an absent table keeps today's behaviour; each valid mode parses; each invalid value fails with a message naming the key; `unknownKeys` does not list the new keys (they are known); a config file carrying the table loads on this binary with zero warnings. Stats — `faketls_handshake` is absent on a fresh proxy (`TestStatsResponseShapeUnchanged` and the raw-shape tests stay untouched and pass), present with the exact counters after handshakes (distinct counts per field, as the obfuscated test does, so a transposed mapping fails), `enforced` reflects the mode; the feature list — update the four literals in `proxy_stats_features_test.go` and the `name` test with `handshake-budget`, plus `assert.True(slices.IsSorted(…))` still passes. Run: FAIL.
- [ ] **Step 2: Implement** the config, wiring, stats object and feature. `GET /secrets/{name}` and `/secrets` are untouched.
- [ ] **Step 3: Docs**: `example.config.toml` (commented section with the three keys and their defaults), `Configuration.md` (table + the accepted-degradation paragraph from the spec), `Security.md` (what the budget defends and what it cannot), `Monitoring.md` (the new stats object and how `observe` is used for a canary).
- [ ] **Step 4:** full `go test -race ./...` for `internal/...` and `mtglib/...`: PASS; `TestPanelContract` untouched and green.
- [ ] **Step 5: Sabotage**: transpose two JSON fields; emit the object when empty; drop the feature string; unsorted insert. Each fails. Restore.
- [ ] **Step 6:** lint (`config verify` then `run`); commit `feat: [defense.handshake-budget], faketls_handshake stats and the handshake-budget feature`.

### Task 8: Gate, box measurement, the pads decision, report (controller task)

**Files:**
- Create: `benchmarks/results/2026-10-07-handshake-scale-after.txt`, `benchmarks/results/2026-10-07-handshake-scale-report.md`
- Modify (only if pads fail the rule): `mtglib/internal/tls/fake/verify.go` and its tests

- [ ] **Step 1: Full gate**: `golangci-lint config verify` then `golangci-lint run`; `go build ./... && go vet ./...`; `go test -count=2 -race ./...`; `govulncheck ./...` if available; golden and snapshot tests unchanged (`git diff origin/main -- '*golden*' '*testdata*'` is empty).
- [ ] **Step 2: Box run after**, same protocol as Task 2, same cells, plus a pads A/B in one binary (`NewCandidate` vs `NewPlainCandidate` sub-benchmarks). Apply the rule: pads stay only if ≥ 10% fewer ns/candidate on the unmatched scan at N=1,000/517 B; otherwise make `NewCandidate` return the plain candidate, delete the pad path and its tests, re-run, and say so in the report.
- [ ] **Step 3: Report** with `benchstat` tables (baseline vs after), the acceptance checks of the spec (hint hit at N=5,000 within 1.3× of N=1; flood tests; many-/64s ceiling), the hint-hit-rate reading from a replayed multi-user scenario, the honest limits (2 vCPU, loopback), and the sabotage log.
- [ ] **Step 4:** whole-branch independent review (fresh reviewer agent, most capable model); fix findings test-first; re-run the gate; commit `bench: ee handshake at scale, before and after`.
