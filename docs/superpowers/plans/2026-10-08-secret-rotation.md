# Rotation of a shared secret with an overlap period — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Retire a leaked shared link without cutting its legitimate holders at once: a new key under the same name, the old key accepted until an absolute `until`, then refused and its live streams closed — strictly additive, and every loss of state kills the old key (R0).

**Architecture:** The config file is the only source of retiring keys (`[[retiring-secret]]`, written by a new `rotate-secret` command through a surgical, re-parse-verified, atomic edit). The engine's immutable `secretSet` holds retiring entries after every primary (one more scan loop, one more hinted position list, one more obfuscated key range), the matched key travels to the server flight, expiry is judged by one high-water `RotationClock` per process, and an overlap ends through `closeStaleConns`' per-stream judgment, whose fast path compares the keys a set *holds*. Registration re-checks the key inside `liveMu` (D16), which also closes today's re-key race. Read-only state is four `omitempty` scalars; the WEB relay only recognises retired capabilities.

**Tech Stack:** Go 1.26.8, `github.com/pelletier/go-toml/v2` v2.4.3 (`unstable.Parser{KeepComments}` for the edit), testify, the repo's `entryHarness`, `dialProxyFrom`/`remoteAddrConn`, the golden FakeTLS trace helpers, the `run_proxy_loop_test.go` harness, `benchstat`.

**Spec:** `docs/superpowers/specs/2026-10-08-secret-rotation-design.md` (revision 3, 32 decisions D1–D32, tests E/D/L/A/C/R/W, §15 decomposition). It is binding; this plan cites its sections instead of restating them. The two reviews that shaped it: `.superpowers/sdd/2026-10-08-secret-rotation/spec-review.md` and `spec-rereview.md`.

## Global Constraints

- **Additive only.** No release-asset name, route, status code, existing JSON field, existing config key or `[secrets]`/`[secret-ad-tags]`/`[secret-limits]` meaning changes. Default `accept-modes` stays `["ee"]`. No SIGHUP handler for `run` (D27), no API write path and no rotate route (D18), no new file written by the proxy, no new event or metric.
- **No wire change.** Not one byte the proxy sends for a primary match changes: `mtglib/proxy_golden_faketls_test.go`, the `mtglib/internal/tls/fake` snapshot tests and `testclient.ClientHello` stay **untouched**; doppelganger pacing defaults untouched.
- **The panel contract (frozen; p-ui runs this binary as a sidecar):** release-asset names; every management route, status code and JSON field; the `PUT /secrets` body; `/stats` decoded non-strictly — **nothing new as a key under `users`**, new data only as the four `omitempty` scalars inside the user object and `SecretInfo`; the usage-state file untouched; `Config.String()` byte-identical for a file without the table; `run --check` over the panel's file reports nothing new; `TestPanelEmittedConfigIsAccepted` (`internal/config/panel_contract_test.go`) untouched and green; `TestStatsOmitemptyShapeUnchanged` (`mtglib/proxy_stats_features_test.go:230–274`) untouched and green — its file is edited by Task 7 inside `TestStatsFeatures` only; a panel re-key stays immediate (`PUT` never turns an old primary into a retiring entry).
- **R0: lost rotation state kills the old key, never revives it.** A problem entry is dropped under `run` (never refuses the load, D4); rule 4 is a warning, not a drop; rule 5 is judged against every syntactically valid entry, expired and dangling included; rule 8's order is fixed (`until` desc, then name, then key bytes); the CLI never rolls a file back.
- **Retiring keys are never printed** — not in logs, errors, API bodies, `/stats`, `Config.String()`, `access` or `rotate-secret` output (D21, §6.1). `mtglib.Secret.String()` **is** the base64url value: never format a `Secret`, `RetiringSecret`, `ConfigRetiringSecret`, `RetiringReport` or `[]retiringDrop` with `%v`/`%s`/`%+v`; never call `(*toml.DecodeError).String()` (print `Error()` only); the CLI prints only the status line of a failed `POST /reload`. Every leak test checks four spellings: the value in hex, the value in base64url, the 16-byte key in hex, the key in base64 (std and url).
- **Exact values:** `MaxRetiringOverlap = 720 * time.Hour`, `MaxRetiringPerSecret = 4`, `MaxRetiringSecrets = 4096`; `maxHintPositions = 32` (the 16 hinted names are unchanged); expiry sweep on the existing `denySweepInterval` (5 s); the behind-clock report threshold 1 s; WEB retired capabilities ≤ 4,096 (scan ≤ 8,192); `until` written by the CLI in UTC `Z` to the second; `--overlap` 0 ≤ D ≤ 720h, no default; lock `<target>.rotate.lock`, temp `<target>.rotate-<8 random hex>.tmp` created `0600`; feature string `secret-rotation`, sorted between `secret-read` and `secrets-api`; deny reason `DenyKeyRevoked` = `"key_revoked"`, logged at Info, no counter, no event. Log lines and fields: spec §6.2 verbatim.
- **Lock order** `reloadMu` → `liveMu` → `tableMu` (`banMu` inner to `liveMu`). The expiry sweep takes `reloadMu` with `TryLock`, never `Lock`. Nothing new takes `reloadMu` under `liveMu`. Streams are snapshotted under `liveMu` and closed outside it.
- **Nil when none.** Every new `secretSet` field is nil/zero when no retiring entry survives (so `primaryCands` is 0 there; the primary/retiring boundary is always `set.primaryEnd()`, Task 1); the doors then run today's loops with no clock read and no extra allocation (allocations identical by `testing.AllocsPerRun` on the door functions in Tasks 3 and 4; the bench rows' allocs/op show no significant change under benchstat in Task 13 — whole-connection rows vary by a few allocs from run to run on unchanged code, so a single-run comparison proves nothing). A `Proxy{}` literal works; a nil `*RotationClock` reads `time.Now`.
- **Clocks and scope.**
  - `checkLimits` keeps `time.Now()` for a user's `ExpiresAt`, and `run --check`, `doctor` and `rotate-secret` use `time.Now()`. The rotation clock governs retiring expiry only (§1.2, §2.3).
  - `Validate()` never calls `GetRetiringSecrets` (D4).
  - The engine never applies rule 4 (§2.1).
  - `rotate-secret` makes no network access except `--reload` (§7.2).
  - `access`, and the WEB relay's serving (`orderedSecrets`, `Lookup`), stay primary-only (§8).
- **Seams** are package-level funcs, no-ops in production (`registerStepHook`'s pattern): `beforeRegisterLockHook`, `afterAttributeHook` (spec §12), plus two this plan adds with reasons (`afterSecretStoreHook`, Task 5; `beforeKeepMergeLockHook`, Task 6). A test that sets one restores it with `t.Cleanup` and does not run in parallel. Per-proxy test hooks follow `afterFairPass` (a field, nil in production).
- **Test first, sabotage every new test** (break the behaviour, watch the named test fail, restore; record each in the task report). **No existing test is weakened:** no assertion removed or loosened, no subtest deleted, skipped or made conditional, no expected `DenyReason` changed. A test that fails honestly is a finding, reported, never patched over.
- **Tools:** Go 1.26.8 (via `GOTOOLCHAIN=go1.26.8+auto`; the MSI's 1.26.5 is not what runs). Pinned golangci-lint 2.13.2: `golangci-lint config verify` THEN `golangci-lint run`; `golangci-lint fmt ./...` after scripted edits. `benchstat` and `govulncheck` are **not on PATH**; prebuilt copies sit in the controller's scratchpad, `C:\Users\Arman\AppData\Local\Temp\claude\C--Users-Arman-Desktop-hakir-Projects-mtg-proxy\740ab1fc-9640-4ec2-b108-4c8c6d2cbd0d\scratchpad\benchstat.exe` and `…\govulncheck.exe`. Tasks 13 and 14 call them by that path; if they are gone, `go install golang.org/x/perf/cmd/benchstat` and `golang.org/x/vuln/cmd/govulncheck` at a pinned version through the module proxy (dl.google.com is unreachable), and if that fails the report says the step was not run.
- **Gate before each task's commit:** `go build ./...`, `go vet ./...`, `go test -count=1 -race` on the packages touched, lint as above. The whole-tree `go test -count=2 -race ./...` runs once, in Task 14. On Windows rapid repeated test runs exhaust local ports: never loop whole-package runs.
- **Commits:** explicit paths only, `git add <paths>` then `git commit -m "<msg>" -- <paths>`; no attribution lines; never amend, reset or rebase; never push, tag or merge. **No CI claim:** GitHub Actions is disabled for this account, so the local gate is the only gate and no report may say "CI green".
- **LF endings** (`.gitattributes`: `* text=auto eol=lf`). A CRLF fixture is built inside its test from the LF one, never committed.
- **Unix-only paths** (chown, mode bits, directory fsync, symlinks, `EBUSY`/`EXDEV` on rename) cannot run on this Windows machine and there is no CI. They run once on the bench box inside Task 13's session (cross-compiled test binaries, no `-race`), or stay an explicit `t.Skip` on Windows recorded in the report as unverified.
- **Bench box** (`penhoon-data`, shared DB host): work only in `/root/mtg-bench` and delete it afterwards; cross-compile locally (`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c`, an env-prefixed command, so through the Bash tool), `scp`, `chmod +x`, `TMPDIR=/root/mtg-bench/tmp`; `ulimit -n 65536`; wait for `ss -Htan state time-wait | wc -l` < 200 between runs (sent as one quoted remote command); same-session A/B alternating old and new binaries; short bounded runs; loopback ports only; no large files left.
- **Sandbox:** single commands only, no `cd` (use `go -C <dir>` and `git -C <dir>`), no `&&` chains or local pipelines.
- **Reports:** each task writes `.superpowers/sdd/2026-10-08-secret-rotation/task-<n>-report.md` (what changed, the sabotage log, anything found). Release notes are hand-written text for the GitHub release description, drafted in `task-12-report.md` and copied into Task 14's `final-report.md` — never a CHANGELOG file.

## Review Focus

Failure modes the spec and both reviews imply that no single headline test covers, most likely first; each is pinned in the task named.

1. **The held-key predicate at the expiry sweep and on a reload after `until`** (B1). A fast path judged at `now` skips the name and strands every old-key stream forever; closing them in `expireRetiring` instead hides the reload path. Task 5: L2, L2b (three variants, with the "overlap ended" line), L6.
2. **The registration re-check loads the set inside `liveMu`** (M1′), right after the Lock and before the ban re-check — never in the pre-lock preamble — and its condition keeps its parentheses, `(cur != attrSet || !retiringUntil.IsZero()) && !accepts(…)`. The L5b sabotage only proves something with the `Load` above `beforeRegisterLockHook`. Task 0 (L5b, re-key variant) and Task 5 (L5b, expiry variant; the no-swap expiry clause).
3. **Task 0's helper adaptation weakens nothing.** The enumeration before/after, the per-helper diff, the formerly vacuous `TestProxyReloadSecrets` subtests now registering for real, and no helper storing a set the test did not (a stored set breaks `TestAProxyWithoutATableHasNoEntries`). Task 0.
4. **Key material in logs, errors and `String()`.** `Secret.String()` is the value; `DecodeError.String()` quotes the document; a `/reload` 500 body is the proxy's error text. Task 2 (drop lines), Task 5 (change log), Task 8a (C1, C7, the C8 config slice), Task 8b (`checkConfig`, doctor, `--check` output), Task 9b (R7), Task 10 (R7 reload half, the full C8 including `access`).
5. **The CLI file-edit hazards:** a header node's empty `Raw`; a block landing inside `[secrets]` so later users become `retiring-secret.<user>`; quoted, dotted and inline keys; CRLF and no final newline; the heading comment of the next table; the single-table typo header; then on disk the symlink, permissions and owner, the lock, the hash check, the mount point, and no copy of the old file. Tasks 9a (R1–R3), 9b (R4–R6).
6. **Clock plumbing through `RotationClock`:** one instance per process, shared by the reloader and the proxy; `NewProxy` resolves it before the initial build; a usable zero value; one read per swap reused by the build, `closeStaleConns` and the change log; the initial build's drops logged only once `proxy` exists. Task 2 (E5), Task 5, Task 8b (E6 through `runProxyWith`).
7. **Revival paths:** rule 4 kept, rule 5 against expired and dangling entries, rule 8's fixed order, a reload with one bad block applying the rest, a `PUT` re-adding an entry a reload removed, a behind-clock reload, the `POST` revert. Task 8a (C9, C12–C14), Task 8b (E6, the bad-block reload), Task 6 (A2, A5).
8. **Multi-key behaviour of budget, hints and `candByName`:** retiring positions for a name whose primary is no candidate (ee → dd), the cap of 32, retiring candidates charged like any other, an expired candidate overcharged but never verified, the inner handshake and the flight on the matched key, the `primaryEnd()` boundary on a set with and without retiring entries. Task 1, Task 3 (D1–D4b, the budget test), Task 4 (index mapping).
9. **The no-retiring path is today's code:** E2 against a frozen copy of today's builder (calling its own frozen `buildCandidates`), loop 1 byte for byte, no clock read, allocations identical by `AllocsPerRun`. Tasks 1, 3, 4, 13.
10. **The downgrade story:** an older binary ignores the table (kills the old key), `--reload` refuses a running binary without `secret-rotation` unless `--force`, the docs say so. Task 10 (R10), Task 12.

---

**Order.** `0 → 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8a → 8b → 9a → 9b → 10 → 11 → 12 → 13 → 14` (17 tasks). The true dependencies: 1←0; 2←1 (it wires `buildSecretSetAt` to the clock); 3←1,2; 4←3 (`attributeMatch`); 5←3,4; 6←5; 7←5; 8a←1 (`mtglib.RetiringSecret`); 8b←2,8a; 9a←8a; 9b←9a; 10←7,8b,9b; 11←8a; 12, 13, 14←all. The spec lets 1 and 2 (and 3 and 4) run in parallel; they are serialised here so that every edited line has one owner: Task 1 builds sets and wires nothing, Task 2 wires the builds to the clock.

### Task 0: The registration re-check, primary form, and the test helpers it breaks

**Files:**
- Modify: `mtglib/secret_limits.go` (`DenyKeyRevoked`, its `String()`), `mtglib/stream_context.go` (`attrSet`), `mtglib/proxy_serve.go` (`attribute` sets `attrSet`; `ServeConn` calls `afterAttributeHook` just before `admit`; `tryRegisterConn`'s re-check and `beforeRegisterLockHook`; `countAdmissionRefusal`; the comment at `:490`), `mtglib/proxy_secrets.go` (`accepts`, primary form)
- Modify (helpers only, never assertions): `mtglib/proxy_reload_test.go` (`registerFakeStream`), `mtglib/proxy_deny_reason_test.go` (`denyProbe.stream`), `mtglib/client_conns_test.go` (`capStream`), the ban probes in `mtglib/proxy_bans_test.go`, every other helper the enumeration names, and the mechanical `t` argument at the `registerFakeStream` call sites in `mtglib/maintenance_test.go` (3), `mtglib/proxy_api_test.go` (2), `mtglib/proxy_api_limits_test.go` (1) and `mtglib/proxy_limits_test.go` (1); rename `TestTheReCheckIsTheFirstStep` → `TestTheBanReCheckPrecedesTheLimits`
- Create: `mtglib/registration_helpers_test.go`; Test: `mtglib/registration_recheck_test.go`

**Interfaces:**
- Produces: `DenyKeyRevoked` (after `DenyBanned`), `String() == "key_revoked"`; `countAdmissionRefusal` logs it and counts nothing, sends no event. `streamContext.attrSet *secretSet` — the set `attribute` matched against; set to nil once `tryRegisterConn` has registered the stream (`matchedSecretKey` is kept).
- Produces: `func (s *secretSet) accepts(name string, key []byte, now time.Time) bool` — false for a nil set or an absent name (binary search of `names`), true when `key` equals the name's primary. Task 1 adds retiring keys.
- Produces: `var beforeRegisterLockHook = func(*streamContext) {}` (called immediately before `p.liveMu.Lock()`); `var afterAttributeHook = func(*streamContext) {}` (in `ServeConn`, after `doEntry` succeeds, before `admit`).
- The check, spec §4.3: the first check under `liveMu` — after `Lock`/`defer Unlock` and the `counted`/`entry`/`refuse` declarations, before the ban re-check and before anything `refuse` must undo: `cur := p.secrets.Load(); if cur != ctx.attrSet && !cur.accepts(ctx.secretName, ctx.matchedSecretKey, time.Now()) { return refuse(DenyKeyRevoked) }`. Task 2 replaces `time.Now()` with `p.rotation.Now()`; Task 5 changes the condition to `(cur != ctx.attrSet || !ctx.retiringUntil.IsZero()) && !cur.accepts(…)`, with exactly these parentheses. With no set stored, `cur` and `attrSet` are both nil and the check is skipped, as it must be for the probes that never store one.
- Produces (test-only, in `registration_helpers_test.go`, which exists from Step 1): `func attributeFromSet(t testing.TB, p *Proxy, sc *streamContext)` — when a set is stored **now**, `sc.matchedSecretKey = set.secrets[i].Key[:]` and `sc.attrSet = set` for `sc.secretName`, and `t.Fatalf` if the name is absent; when no set is stored, it leaves both nil. `func registerFakeStream(t testing.TB, p *Proxy, name string) *streamContext` attributes through it and `require`s `DenyNone`.

- [ ] **Step 1: Failing tests** (`registration_recheck_test.go`, serial where a hook is set):
  - `TestARekeyAfterAttributionIsRefusedAtRegistration` (L5, re-key variant): through the real FakeTLS door and an obfuscated `[[listener]]`, `afterAttributeHook` runs `ReplaceSecrets` re-keying the name. The stream is refused with `deny_reason=key_revoked` on the line `connection denied by per-user limit`, never appears in `liveConns`, is closed after the server's flight on FakeTLS, and takes `denyObfuscated` on the other door (`obfuscated.denied` +1).
  - `TestARekeyJustBeforeTheRegistrationLockIsRefused` (L5b, re-key variant): `beforeRegisterLockHook` runs a **complete** `ReplaceSecrets`, from `Store` to the end of its walk. `tryRegisterConn` returns `DenyKeyRevoked`, the stream is not in `liveConns`, and the ledger is as it was.
  - `TestARevokedKeyFromABannedPlaceIsRefusedAsKeyRevoked` (L7, second half): the key re-check precedes the ban re-check.
  - `TestAnUnrelatedSwapBeforeRegistrationStillAdmits`: `afterAttributeHook` runs a swap that keeps the name's key (an ad-tag change); the stream registers with `DenyNone`.
  - `TestKeyRevokedIsLoggedAndNotCounted`: `ip_limit_refused` and `client_conns_refused` do not move; no event.
  - `TestRegistrationReleasesTheAttributedSet`: after `admit`, `attrSet == nil` and `matchedSecretKey` is unchanged.
  - `TestAcceptsPrimaryForm`: nil set, absent name, other key, the primary.
  - Run: FAIL (undefined).
- [ ] **Step 2: Implement** the check, reason, field, seams, `accepts`, and the comment at `proxy_serve.go:490` (key re-check first, then the ban re-check, which still precedes the cap and the limit). Leave every helper untouched.
- [ ] **Step 3: Enumerate (before).** Run `go test ./mtglib/ -count=1 -json` once, with stdout redirected to `.superpowers/sdd/2026-10-08-secret-rotation/task-0-before.jsonl` (a redirect, not a pipeline). Grep it for `"Action":"fail","Package":"[^"]*","Test":"[^"]*"`; a parent test appears beside its failing subtests. Record the list in the report; the reviewer measured about 37 tests. The Step 1 tests pass in this run. The command exits non-zero by design; the redirect still writes the file.
- [ ] **Step 4: Adapt the helpers, never the assertions.** Every helper that hand-builds a stream attributes it with `attributeFromSet` against the set stored when the stream is built. `registerFakeStream` takes `t` and requires `DenyNone`; this changes its call sites mechanically. `newDenyProbe` stores no set. With none stored, `cur` and `attrSet` are both nil, so the check is skipped and such probes register as today. `denyProbe.stream` attributes through `attributeFromSet` only when a set is stored, and **no helper ever stores a set**: storing one breaks the bare half of `TestAProxyWithoutATableHasNoEntries` (`proxy_client_table_test.go:532–539`, "no secret set, no limits to read, no entry"). A test that hands `attribute` a separately generated set for the same name, or builds its stream before storing its set, now meets a different (or no) key and is refused: that is D16 working. If the test is not about a key change, its fixture is changed to use the stored set's key (or to build the stream after the set is stored). If it is about one, stop and report it. The subtests that passed vacuously ("added secret … disturbs nothing" and the alice half of "removed secret …" in `TestProxyReloadSecrets`) must now register for real and pass; a failure is a finding. Rename B's test, with its assertions byte-identical.
- [ ] **Step 5: Enumerate (after).** Run the same command once, with stdout to `task-0-after.jsonl`. The Grep must find nothing. Then run `go test -count=1 -race ./mtglib/`; this is Step 7's gate run for `./mtglib/` and is not repeated. Do not run more whole-package passes than these, because of port exhaustion.
- [ ] **Step 6: Sabotage** (each run restricted with `-run` to the named tests, never a whole-package pass): move the `Load` into the pre-lock preamble, **above the `beforeRegisterLockHook(ctx)` call** (L5b fails while L5 passes; record both — a `Load` placed between the hook and the `Lock` reads the hook's new set and proves nothing); drop the check (L5 and L5b fail); refuse whenever `cur != attrSet` (the unrelated-swap test fails); put it after the ban re-check (the banned-place test fails); count `key_revoked` as `ip_limit` (the counting test fails); keep `attrSet` after registration (the release test fails); revert one helper so it builds a stream without a key, and run the enumeration command with `-run` restricted to that helper's tests: they appear as `fail` again. Restore each.
- [ ] **Step 7: Gate** (build, vet, lint; Step 5's `-race` run stands for the tests), then commit `fix(mtglib): a stream registers only under a key its secret still accepts`.

**Model:** opus. The placement inside `liveMu` and the per-helper no-weakening judgment are the whole task. **Review:** extra scrutiny. Check the per-helper diff and the before and after lists, confirm no helper stores a set the test did not, and confirm the `Load` sits below the `Lock`.

### Task 1: Set building

**Files:**
- Create: `mtglib/secret_rotation.go` (types, constants, `retiringEntry`, `retiringDrop`, `secretMatch`, the retiring half of `buildSecretSetAt`, the set helpers)
- Modify: `mtglib/proxy_secrets.go` (`secretSet` fields, `buildSecretSet` → wrapper, `toConfig`, `accepts`, `coverHosts`), `mtglib/proxy_opts.go` (`SecretConfig.Retiring`, `ProxyOpts.RetiringSecrets`), `mtglib/proxy_api.go` (`forget`)
- Test: `mtglib/secret_rotation_set_test.go`, `mtglib/proxy_secrets_frozen_test.go`

**Interfaces:**
- Produces: `type RetiringSecret struct{ Name string; Secret Secret; Until time.Time }`, using the doc comment in spec §2.1. Also produces the three `MaxRetiring*` constants.
- Produces: `SecretConfig.Retiring []RetiringSecret` and `ProxyOpts.RetiringSecrets []RetiringSecret`. Each holds the complete list, and nil means none, wherever it is consumed. The field doc says so and adds the embedder note: a `ReplaceSecrets` with a nil `Retiring` ends every overlap until the file's next reload grants it again (§5.1).
- Produces: `type retiringEntry struct{ nameIdx int; secret Secret; until time.Time }`.
- Produces: `type retiringDrop struct{ name string; until time.Time; reason string }`. It never holds a key. The reasons are constants `"expired"`, `"dangling"`, `"same_as_primary"`, `"duplicate"`, `"key_of_other_secret"` and `"over_cap"`.
- Produces: `func buildSecretSetAt(secrets map[string]Secret, perSecret map[string][AdTagLength]byte, global *[AdTagLength]byte, limits map[string]SecretLimits, retiring []RetiringSecret, now time.Time) (*secretSet, []retiringDrop)`.
  - The primaries are built exactly as today.
  - Each handed entry is classified in the order of the §1.3 rules 2, 3, 5, 6, 7 and 8. Rule 5's population is every handed entry plus every primary, with expired and dangling entries included. Every colliding retiring entry is dropped, and a primary never is.
  - Rule 7 keeps the later `until`. Rule 8 keeps the 4 latest per name, then the 4,096 latest overall, with ties broken by name and then by key bytes.
  - Drops are returned in input order.
  - `buildSecretSet(…)` becomes `buildSecretSetAt(…, nil, time.Time{})`'s set.
- Produces: the new `secretSet` fields, verbatim from §2.2: `retiring`, `retiringOf`, `primaryCands`, `candRetiring`, `retiringCands` and `retiringNext`.
  - `primaryCands` is 0 on a set with no retiring entry (E2: every new field nil or zero), so it is never used alone as a bound. `func (s *secretSet) primaryEnd() int { return len(s.cands) - len(s.candRetiring) }` is the primary/retiring boundary, used by `matchAt`, `verifyHinted` and both scan loops.
  - `hostnames` and `p.coverHosts(set)` also take the host of every kept ee retiring entry, after the primaries and deduplicated.
  - `frontHost` and `SecretsCanFront` stay primary-only.
- Produces: `type secretMatch struct{ idx int; key *[SecretKeyLength]byte; retiring int }`. `retiring` is an index into `set.retiring`, or −1 for a primary. `key` points into the set's own arrays. Three constructors:
  - `(s *secretSet) primaryMatch(i int) secretMatch`;
  - `(s *secretSet) matchAt(pos int) secretMatch`, for a candidate position;
  - `(s *secretSet) retiringMatch(r int) secretMatch`.
- Produces: `accepts` extended. It also accepts one of the name's `retiringOf` entries with an equal key when `now.Before(until)`. `func sameHeldKeys(oldSet, newSet *secretSet, name string) bool`:
  - "held" means the primary plus every retiring key the set holds, with no clock;
  - held is ∅ for a name a set lacks, and a nil set lacks every name;
  - the result is true only when both held sets are non-empty and equal as sets.
- Produces: `toConfig()` fills `Retiring` (nil when there are none). `(c *SecretConfig) forget(name)` also removes the name's `Retiring` entries.
- `NewProxy` and the swap keep calling `buildSecretSet`, so no retiring entry reaches a live set until Task 2.

- [ ] **Step 1: Failing tests:**
  - `TestTheEngineAppliesTheRetiringRules` (E1). It is a table with one case per reason, giving the surviving entries and the `retiringDrop`s. Under rule 5 both colliding entries are dropped, even when the other one is expired or dangling, and the primary is untouched. One row is an entry whose `until` is more than 720 h after `now`: the engine keeps it, since it never applies rule 4 (§2.1).
  - `TestRetiringEntriesAreOrderedDeterministically`: a shuffled input gives identical `retiring`, `cands`, `candRetiring` and `retiringCands`.
  - `TestRetiringCandidatesFollowEveryPrimary`:
    - `cands[:primaryEnd()]` equals the no-retiring set's `cands`, and with retiring entries `primaryCands == primaryEnd()`;
    - only ee entries become candidates;
    - `candIdx` of a retiring position is its name's index;
    - `retiringCands[name]` is in `retiring` order.
  - `TestRetiringHostsJoinTheGateAndTheCoverHostsButNeverFront`. The test also covers a set whose only ee key is retiring, for which `SecretsCanFront` is unchanged.
  - `TestRetiringNextIsTheEarliestKeptUntil`.
  - `TestTheOverCapOrderIsFixed`: 4,097 entries with one `until` are dropped by name, then by key bytes. The per-name cap keeps the 4 latest.
  - `TestASetWithoutRetiringIsTodaysSet` (E2):
    - `frozenBuildSecretSet` and `frozenBuildCandidates` are copied from `git show 8577930:mtglib/proxy_secrets.go` into `proxy_secrets_frozen_test.go`. They are verbatim except the two function names and the one call inside `frozenBuildSecretSet`, which calls `frozenBuildCandidates`: a call to the live `buildCandidates` would make E2 blind to a change there. They are never regenerated;
    - the fixtures are those of `proxy_secrets_candidates_test.go`, plus ad tags and limits;
    - names, secrets, hostnames, `cands` (compared by value), `candIdx`, `candByName`, `hosted`, `frontHost`, `adTags`, `globalAdTag`, `limits` and `clientControl` must all be equal;
    - every new field must be nil or zero.
  - `TestToConfigRoundTripsRetiringEntries` (E3) and `TestForgetDropsTheNamesRetiringEntries` (E4).
  - `TestMatchesPointIntoTheSet`: each constructor's `idx`, the `key` pointer and `retiring`, on a set without retiring entries (where `primaryEnd() == len(cands)` and `primaryCands == 0`) as well as one with them.
  - `TestAcceptsJudgesRetiringKeysAtNow`: `now == until` refuses.
  - `TestHeldKeysIgnoreTheClock`:
    - the same keys with other `until`s give true;
    - a removed retiring key gives false;
    - a name absent from either set gives false.
  - Run: FAIL.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Sabotage.** Each item makes a named test fail:
  - change today's no-retiring build (drop the repeat-key rule in `buildCandidates`, reorder hostnames) — E2 must fail;
  - use `primaryCands` as the boundary in `matchAt` (`TestMatchesPointIntoTheSet`, no-retiring case);
  - apply the 720 h cap in the engine (E1's rule-4 row);
  - put retiring candidates first;
  - judge rule 5 against unexpired entries only;
  - break rule-8 ties by input order;
  - keep the earlier `until` for a duplicate;
  - let a retiring host become `frontHost`;
  - leave `Retiring` out of `toConfig`;
  - make `forget` keep entries;
  - use `!now.After(until)` as the boundary;
  - judge held keys at `now`.

  Restore after each.
- [ ] **Step 4: Gate**, then commit `feat(mtglib): a secret set that holds retiring keys after its primaries`.

**Model:** opus. The rule order, determinism and the primary-wins invariant decide R0 at engine level. **Review:** extra scrutiny: nil-when-none, the frozen copy really frozen, `frontHost`/`SecretsCanFront` untouched.

### Task 2: The rotation clock, and the builds that read it

**Files:**
- Create: `mtglib/rotation_clock.go`
- Test: `mtglib/rotation_clock_test.go`, `mtglib/proxy_rotation_wiring_test.go`
- Modify: `mtglib/proxy_opts.go` (`RotationClock`), `mtglib/proxy.go` (`rotation` field, `NewProxy`), `mtglib/proxy_secrets.go` (`swapSecretConfigLocked`, `logRetiringDrops`), `mtglib/proxy_serve.go` (the re-check reads `p.rotation.Now()`), `internal/cli/run_proxy.go`, `internal/cli/run_proxy_loop_test.go` (`runInBackground` passes `time.Now`), and every other caller of `runProxyWith`/`makeSecretsReloader`

**Interfaces:**
- Produces: `type RotationClock struct{ now func() time.Time; mark atomic.Int64; behind atomic.Bool; onBehind func(by time.Duration) }`. Constructor: `func NewRotationClock(now func() time.Time, onBehind func(time.Duration)) *RotationClock`.
- Produces: `func (c *RotationClock) Now() time.Time`, following spec §2.3:
  - a nil receiver returns `time.Now()`;
  - otherwise it takes `source` (`c.now`, or `time.Now` when nil), returns the larger of `source` and `mark`, and advances `mark` by CAS;
  - when `source` is more than 1 s behind `mark`, a CAS of `behind` from false to true calls `onBehind(mark−source)` once per episode; a nil `onBehind` logs nothing;
  - when `source` ≥ `mark`, `behind` resets;
  - the zero value is a working high-water clock on `time.Now`.
- Produces: `ProxyOpts.RotationClock *RotationClock` and `Proxy.rotation *RotationClock`. `NewProxy` resolves the clock right after its logger (`proxy.go:182`) and before the initial build: the option if set, otherwise `NewRotationClock(time.Now, …)` logging through the proxy's logger. The initial set is then built with `buildSecretSetAt(…, opts.RetiringSecrets, clock.Now())`. Its drops are kept and logged by `proxy.logRetiringDrops` once `proxy` is constructed: the build at `proxy.go:185` precedes `proxy := &Proxy{…}` at `:207`.
- Produces: `swapSecretConfigLocked` reads `now := p.rotation.Now()` **once** and builds with `buildSecretSetAt(…, cfg.Retiring, now)`. Task 5 reuses this one `now` for `closeStaleConns` and the change log. `func (p *Proxy) logRetiringDrops(drops []retiringDrop)` logs `a retiring key was ignored` with `secret_name` and `reason`:
  - Warning for `dangling`, `key_of_other_secret` and `over_cap`;
  - Info for `same_as_primary`, `duplicate` and `expired`;
  - it touches `p.logger` only when there is a line to write: hand-built `Proxy{}` literals such as `newReloadTestProxy` have a nil logger.
- Produces: the behind Warning `the wall clock is behind the latest time seen; rotation overlaps are judged by the latest time`, with `behind_by`, from both `NewProxy` and `run`.
- Produces: `func runProxyWith(stop <-chan struct{}, conf *config.Config, version, configPath string, listen listenFunc, now func() time.Time) error`. `runProxy` passes `time.Now`.
  - Right after `makeLogger` it builds `clock := mtglib.NewRotationClock(now, onBehind)`.
  - `makeSecretsReloader(configPath string, logger mtglib.Logger, clock *mtglib.RotationClock)` receives the clock, and the reloader starts reading it in Task 8b.
  - It sets `opts.RotationClock = clock`. There is no package global.

- [ ] **Step 1: Failing tests** (E5 and the wiring):
  - `TestRotationClockNeverRunsBackwards`.
  - `TestRotationClockReportsEachBehindEpisodeOnce`: once per episode, with the gap. It fires again after the source passes the mark and falls behind anew, and never for a gap of 1 s or less.
  - `TestANilRotationClockReadsTheWallClock`.
  - `TestTheZeroRotationClockIsAHighWaterClock`: `&RotationClock{}` does not panic and is non-decreasing.
  - `TestNewProxyJudgesTheInitialSetByItsClock`: with `until` in the real future (`time.Now()+time.Hour`) and the fake clock at `until+time.Hour`, the entry is absent and an Info `expired` drop is logged; with the fake before `until` the entry is present. (A `until` in the real past would let the sabotage "build the initial set before resolving the clock" pass.)
  - `TestNewProxyBuildsAClockWhenNoneIsGiven`.
  - `TestASwapReadsTheClockOnce`: a counting source is read once per `ReplaceSecrets`.
  - `TestEngineDropsAreLoggedByReasonWithoutKeys`: the levels, the fields, and none of the four spellings in any line.
  - Run: FAIL.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Sabotage.** Each item makes a named test fail:
  - let `Now` follow the source backwards;
  - report every behind read;
  - dereference `c.now` in the zero value;
  - build the initial set before resolving the clock;
  - read the clock twice in the swap;
  - log a drop with its secret.

  Restore after each.
- [ ] **Step 4: Gate** (`./mtglib/ ./internal/cli/`), then commit `feat: one high-water rotation clock per process`.

**Model:** sonnet. The algorithm and every wiring point are spelled out, and the task is small. **Review:** task review (one instance per process; the zero value; no global; `NewProxy`'s order — clock, build, construct, then log; one read per swap).

### Task 3: The FakeTLS door

**Files:**
- Modify: `mtglib/proxy_entry.go` (`doFakeTLSHandshake`, `hintedPositions`, `verifyHinted`, `scanCandidates`, `completeFakeTLS`), `mtglib/proxy_serve.go` (`attributeMatch`), `mtglib/stream_context.go` (`retiringUntil`), `mtglib/handshake_hints.go` (`maxHintPositions`), `mtglib/proxy_secrets_candidates_test.go` (its eight `scanCandidates` calls, at lines 77, 342, 347, 537, 546, 572, 591 and 595, pass `nil`, mechanically)
- Test: `mtglib/proxy_entry_retiring_test.go`, `mtglib/proxy_entry_allocs_test.go`

**Interfaces:**
- Consumes: the Task 1 set fields, `matchAt`, `primaryMatch`, `Proxy.rotation`.
- Produces: `const maxHintPositions = 32`.
- Produces: `type helloNow struct{ clock *RotationClock; at time.Time; read bool }` with `func (h *helloNow) get() time.Time`. It reads the clock on its first call only; a nil receiver reads `time.Now()`. `doFakeTLSHandshake` keeps one as a stack value and passes its address, which must not allocate.
- Produces: `func (p *Proxy) verifyHinted(parsed *fake.Parsed, set *secretSet, positions []int, now *helloNow) (pos, tried int)` and `func (p *Proxy) scanCandidates(parsed *fake.Parsed, set *secretSet, skip func(pos int) bool, now *helloNow) (pos, tried int)`. They stay methods, because they read `p.tolerateTimeSkewness`. A retiring position (`at ≥ set.primaryEnd()`) with `until ≤ now.get()` is passed over, unverified and uncounted. In `scanCandidates`:
  - loop 1 runs over `cands[:set.primaryEnd()]` and is today's loop byte for byte, with no clock;
  - loop 2 runs over `cands[set.primaryEnd():]`.
- Produces: `(p *Proxy) hintedPositions` (still a method: it reads `p.hints` and `p.bans`), which for each hinted name gives:
  - `candByName[name]` when present;
  - then `set.retiringCands[name]`, **whether or not the primary is a candidate**;
  - the result is deduplicated and capped at `maxHintPositions`;
  - it allocates exactly as today when the set holds no retiring entry.
- Produces: `completeFakeTLS(ctx, rewind, set, parsed, m secretMatch) bool`, which sends `fake.SendServerHello(ctx.client(), m.key[:], …)`.
- Produces: `func (p *Proxy) attributeMatch(ctx *streamContext, set *secretSet, m secretMatch) DenyReason`. It sets `matchedSecretKey = m.key[:]`, `attrSet = set` and `retiringUntil` (`set.retiring[m.retiring].until`, zero for a primary). It reads name, ad tag, limits, `ipLimit` and `clientConns` from `m.idx`.
  - This is the spec's `attribute(ctx, set, m)`.
  - `attribute(ctx, set, i int)` stays as `attributeMatch(ctx, set, set.primaryMatch(i))`, so that the six test call sites of `attribute` compile unchanged.
- Produces: `streamContext.retiringUntil time.Time`.
- The budget is unchanged: `reserveScan(…, len(set.cands)-tried, …)`.

- [ ] **Step 0:** Before any edit, on the unmodified code:
  - measure, with a scratch test that is not committed, `testing.AllocsPerRun` of `hintedPositions`, then `verifyHinted`, then `scanCandidates` on a no-retiring set, for a match, a miss and a hinted hello; record the counts in the report;
  - run `go test -run '^$' -bench 'BenchmarkDoorHandshake/ee-unpaced' -benchmem -benchtime 20x -count 5 ./mtglib/` and record each row's allocs/op spread. On unchanged code these rows vary by a few allocs/op from run to run (283 against 279 was measured), so this is context, not a bar;
  - ee rows only; dd belongs to Task 4.
- [ ] **Step 1: Failing tests:**
  - `TestAnOldLinkCompletesARealHandshake` (D1). Alice is rotated K1→K2, with K1 retiring.
    - A K1 client completes the FakeTLS handshake and the inner obfuscated2 handshake, and relays.
    - The flight's digest verifies with K1 (`assertFakeTLSDigest`) and not with K2.
    - Its masked golden trace (`goldenFlightLines`) equals that of a proxy whose primary is K1.
    - The repo has no deterministic-noise seam. The masked trace plus the digest is what "byte-identical" means here, and no production seam is added.
  - `TestAnOldLinkPastUntilIsFrontedLikeAWrongSecret` (D2): the clock is past `until` and there has been no swap. The cover site receives the same bytes as for a wrong key, and the expired candidate is never verified (verification count).
  - `TestAPrimaryMatchCostsTheSameWithRetiringEntries` (D3).
  - `TestAHintedOldLinkMatchesInTwoVerifications` (D4): no scan charge.
  - `TestHintedPositionsAreCappedAt32`: 16 hinted names, each with a primary and 4 retiring keys. Positions past the cap are still found by the scan.
  - `TestAnEeToDdRotationKeepsTheOldLinksHint` (D4b): 1 hinted verification, no scan charge.
  - `TestAHostChangingRotationPassesTheOldHostUntilItsEntryLeaves` (D7): during the overlap the old SNI passes the gate. After a `ReplaceSecrets(toConfig())` at `now ≥ until` it is fronted to `frontHost`.
  - `TestRetiringCandidatesAreChargedLikeAnyOther` (D13): the reservation counts `len(cands) − tried`, retiring included. An expired candidate still in the set is charged but never verified.
  - `TestAScanWithoutRetiringNeverReadsTheClock`: a counting clock reads 0 times for a match, a miss and a hinted hello on a no-retiring set, and at most once per hello otherwise.
  - `TestTheFakeTLSDoorAllocatesAsBefore` (in `proxy_entry_allocs_test.go`): `testing.AllocsPerRun` of `hintedPositions`, `verifyHinted` and `scanCandidates` on a no-retiring set equals the Step 0 counts exactly.
  - The golden tests, `TestFakeTLSAdmitsOnlyHostedSecrets` and the hint and budget suites stay untouched and green.
  - Run: FAIL.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Sabotage.** Each item makes the named test fail:
  - retiring candidates first (D3);
  - never add a hinted name's retiring positions (D4);
  - skip a name's retiring positions when its primary is no candidate (D4b);
  - cap at 16 (cap test);
  - verify an expired candidate (D2);
  - send the flight with the primary's key (D1);
  - read the clock in loop 1 (no-clock test);
  - charge only primaries (budget test);
  - collect a name's retiring positions into a second slice even when the set has none (the allocation test);
  - loop over `cands[:set.primaryCands]` (every existing door test fails on a no-retiring set).

  Restore after each.
- [ ] **Step 4: Gate.** `TestTheFakeTLSDoorAllocatesAsBefore` passes. Re-run the Step 0 benchmark with `-count 5` and report each row's allocs/op against Step 0's spread; never compare a single run. Commit `feat(mtglib): the ee door accepts a retiring key and answers with it`.

**Model:** opus. This is the hot path, the budget arithmetic and the flight's key. **Review:** extra scrutiny: loop 1 byte-identical, the `primaryEnd()` boundary, budget arithmetic, golden flight, ee → dd hinted, `AllocsPerRun` counts.

### Task 4: The obfuscated door

**Files:**
- Modify: `mtglib/proxy_entry.go` (`doObfuscatedEntry`), `mtglib/proxy.go` (the start-up warning)
- Test: `mtglib/proxy_entry_retiring_obfs_test.go`

**Interfaces:**
- Produces: `func obfuscatedKeys(set *secretSet, clock *RotationClock) (keys [][]byte, keyRetiring []int)`, from spec §3.2 verbatim:
  - capacity is `len(secrets)+len(retiring)`;
  - primaries come first, then the unexpired retiring keys;
  - `keyRetiring` is nil and the clock is not read when the set has no retiring entry;
  - `doObfuscatedEntry` calls it only inside today's `if allowed` branch, so a rate-limited peer gets no keys and no clock read.
- Produces: `func (s *secretSet) obfuscatedMatch(index int, keyRetiring []int) secretMatch`. An index below `len(secrets)` gives `primaryMatch`; otherwise it gives `retiringMatch(keyRetiring[index-len(secrets)])`. The door attributes through `attributeMatch`, and every refusal takes `denyObfuscated`.
- Produces: `NewProxy` warns once for each retiring dd or plain entry that no listener honours. It uses the existing `secret is not served by any listener; …` wording, with `secret_name` and `mode`.

- [ ] **Step 0:** On the unmodified code, measure with a scratch test (not committed) `testing.AllocsPerRun` of the inline key-list build of `doObfuscatedEntry` (1 today), and run the `BenchmarkDoorHandshake/dd` rows with `-count 5` to record their allocs/op spread, as in Task 3.
- [ ] **Step 1: Failing tests:**
  - `TestOldDdAndPlainKeysAttributeToTheirName` (D5): several names, each with a retiring dd or plain key. Each old key is billed to its own name, with that name's stats, ad tag and limits, and relays under its own key. After `until` it is refused through `denyObfuscated` (`obfuscated.denied` +1).
  - `TestTheObfuscatedIndexMappingIsExact`: index `len(secrets)+j` maps to `keyRetiring[j]`, and expired entries are not in the list.
  - `TestAModeChangingRotationServesBothDoors` (D6): the old dd key on the listener and the new ee key on `bind-to`.
  - `TestTheObfuscatedKeyListAllocatesAsBefore`: `testing.AllocsPerRun` of `obfuscatedKeys` on a no-retiring set equals the Step 0 count (1). `keyRetiring` is nil and the clock is not read.
  - `TestARateLimitedPeerGetsNoKeyList`: a peer over its failure budget never reaches `obfuscatedKeys` (a counting clock on a set with retiring entries reads 0 times).
  - `TestAnUnservedRetiringKeyIsWarnedAtStart`.
  - Run: FAIL.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Sabotage.** Each item makes a named test fail:
  - shift the mapping by one;
  - list expired entries;
  - read the clock when there are none;
  - allocate `keyRetiring` when there are none (the allocation test);
  - build the key list before the `if allowed` check (the rate-limited test);
  - drop the warning.

  Restore after each.
- [ ] **Step 4: Gate.** `TestTheObfuscatedKeyListAllocatesAsBefore` passes; the dd rows' allocs/op, re-run with `-count 5`, are reported against Step 0's spread, never as a single run. Commit `feat(mtglib): the obfuscated door accepts a retiring key of any mode`.

**Model:** sonnet. §3.2 gives the code, and the tests pin the mapping. **Review:** task review (off-by-one, allocation).

### Task 5: Lifecycle — the per-stream close, the expiry sweep, the change log

**Files:**
- Modify: `mtglib/proxy_secrets.go` (`closeStaleConns`, `swapSecretConfigLocked`, `expireRetiring`, the sweep case, `logRetiringChanges`), `mtglib/proxy_serve.go` (the re-check's condition), `mtglib/proxy.go` (`staleSkipHook`; `NewProxy` logs the initial entries)
- Test: `mtglib/retiring_lifecycle_test.go`; a subtest added to `mtglib/registration_recheck_test.go`

**Interfaces:**
- Produces: `func (p *Proxy) closeStaleConns(oldSet, newSet *secretSet, now time.Time) map[string]int`, from spec §4.1. For each name in `liveConns`:
  - if the name is absent from `newSet`, close all its streams;
  - if `sameHeldKeys(oldSet, newSet, name)`, skip the name and call `p.staleSkipHook(name)` when it is set;
  - otherwise close each stream whose `matchedSecretKey` `newSet.accepts(name, key, now)` refuses.

  Streams are snapshotted under `liveMu` and closed outside it. The function returns the number closed per name.
- Produces: `var afterSecretStoreHook = func(*secretSet) {}`, called in the swap immediately after `p.secrets.Swap(newSet)` and before anything takes `liveMu`.
  - It is a test seam this plan adds. L4's "kept" half needs a stream to register **between** `Store` and the walk, and L5b's seam runs a whole swap before the stream locks, so it cannot place one there.
- Produces: the swap passes its one `now` (Task 2) to `closeStaleConns` and to `func (p *Proxy) logRetiringChanges(oldSet, newSet *secretSet, now time.Time, closed map[string]int)`. That function implements spec §6.3: it diffs by (name, key) and never logs a key. The lines:
  - a new entry gives `secret accepts a previous key until its overlap ends` (`secret_name`, `until`);
  - an entry that left with `until ≤ now` gives `previous key of the secret is no longer accepted: overlap ended` (`secret_name`, `until`, `closed`);
  - any other departure gives `previous key of the secret is no longer accepted` (`secret_name`, `reason=removed`, `closed`);
  - `closed` is the name's count, which `closeStaleConns` returns per name;
  - no line is written when nothing changed;
  - `NewProxy` calls it with a nil old set, after `proxy` is constructed;
  - like Task 2's `logRetiringDrops`, it touches `p.logger` only when it has a line to write (hand-built `Proxy{}` literals have a nil logger).
- Produces: `func (p *Proxy) expireRetiring()`, which is spec §4.2's pseudocode verbatim, with `TryLock`. It is called from the sweep case before `closeDeniedConns`.
- Produces: the re-check becomes `if (cur != ctx.attrSet || !ctx.retiringUntil.IsZero()) && !cur.accepts(ctx.secretName, ctx.matchedSecretKey, p.rotation.Now()) { return refuse(DenyKeyRevoked) }`, so a key that expires without a swap is refused too. The parentheses are required: without them `&&` binds first and every stream is refused after any unrelated swap. The `Load` stays under the `Lock`.
- Produces: `Proxy.staleSkipHook func(name string)`. It is nil in production and set by a test before its swap.

- [ ] **Step 1: Failing tests:**
  - `TestARotationKeepsEveryLiveStream` (L1).
  - `TestTheExpirySweepClosesExactlyTheOldKeyStreams` (L2). The name must **not** reach `staleSkipHook`.
  - `TestAReloadAfterUntilClosesTheOldKeyStreams` (L2b), in three subtests:
    - *reload only, sweep never started*: with the reloader returning the entry filtered (the config layer's view), and again with it present (the engine drops it as `expired`). The "overlap ended" line carries `closed` = N;
    - *sweep only*;
    - *a failed reload holds the lock, then the sweep*: `expireRetiring()` is called while a `ReloadSecrets`, whose reloader blocks on a channel and then fails, holds `reloadMu`. Nothing is closed. After the failure, `expireRetiring()` closes them.

    In every variant no K1 stream survives, and a later unrelated swap leaves the K2 streams open.
  - `TestAnEndOverlapReloadClosesThemAtOnce` (L3).
  - `TestARekeyWithoutOverlapClosesOnlyStreamsFromBeforeTheSwap` (L4): the K1 streams registered before the swap are closed. A K2 stream registered inside `afterSecretStoreHook` is kept.
  - `TestARetiringKeyRevokedAfterAttributionIsRefused` (L5, retiring variant, both doors).
  - `TestAnExpiringKeyJustBeforeTheRegistrationLockIsRefused` (L5b, expiry variant): `beforeRegisterLockHook` runs a complete expiry swap with the clock past `until`. The stream is refused `key_revoked` and is absent from `liveConns`.
  - `TestAKeyThatExpiresWithoutASwapIsRefusedAtRegistration`: `attrSet == cur`, `now ≥ until`.
  - `TestAnUnrelatedSwapBeforeRegistrationStillAdmits` (Task 0's, in `registration_recheck_test.go`) gains its retiring variant as a subtest: a stream on an unexpired retiring key across an ad-tag swap registers with `DenyNone`.
  - `TestTheFastPathFollowsHeldKeys` (L6):
    - an unrelated change skips the name;
    - a held change whose accepted sets are equal at `now` never skips it;
    - a name absent from the old set never skips.
  - `TestBanAndKickReachBothKeys` (L7, first half).
  - `TestBothKeysShareTheQuota` (L8).
  - `TestTheExpirySweepNeverWaitsForReloadMu` (L9): with `reloadMu` held by the test, `expireRetiring` returns at once, and the maintenance loop's `closeDeniedConns` still closes a disabled user's stream on that tick.
  - `TestTheRotationChangeLog`: the start line, a new entry, "overlap ended", "removed", silence for an unrelated swap, and no key spelling anywhere.
  - `TestASwapStillReadsTheClockOnce`.
  - Run: FAIL.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Sabotage**, using spec §12's list for this task. Each item makes the named test fail:
  - a key-blind `closeStaleConns` (L1);
  - a name-only close, on removal alone (L2, L4);
  - drop the `expireRetiring` call from the sweep (L2);
  - a fast path judged at `now` (L2, L2b);
  - closing expired streams in `expireRetiring` while `closeStaleConns` stays clock-judged (L2b's reload-only variant);
  - "overlap ended" classified by the engine's drop reason (L2b with the filtered reloader);
  - `Lock` instead of `TryLock` (L9);
  - the `Load` moved into the preamble above `beforeRegisterLockHook` (L5b expiry; between the hook and the `Lock` it proves nothing);
  - the `retiringUntil` clause dropped (the no-swap test);
  - the parentheses dropped from the condition (the unrelated-swap test: the stream is refused);
  - the fast path taken for a name absent from the old set (L6).

  Restore after each.
- [ ] **Step 4: Gate**, then commit `feat(mtglib): an overlap's end closes exactly the old key's streams`.

**Model:** opus. This is B1, the lock order, and the M1′ condition again. It is the largest engine task; if the reviewer budget is tight, `logRetiringChanges` and `TestTheRotationChangeLog` may land as a separate commit reviewed on its own. **Review:** extra scrutiny: the held-key predicate, one `now` per swap, the `Load` still inside `liveMu`, the condition's parentheses, lock order.

### Task 6: API mutations keep the file's grants

**Files:** Modify: `mtglib/proxy_api.go` (`replaceSecretsKeepingRetiring`, `handlePutSecrets`, the `ReplaceSecrets` doc). Test: `mtglib/proxy_api_retiring_test.go`

**Interfaces:**
- Produces: `func (p *Proxy) replaceSecretsKeepingRetiring(cfg SecretConfig) error`. It calls `beforeKeepMergeLockHook()`, takes `reloadMu`, and sets `cfg.Retiring` to the current set's entries whose names `cfg.Secrets` keeps, read from `toConfig()` under the lock. Then it calls `swapSecretConfigLocked`. `handlePutSecrets` is its only caller.
- Produces: `var beforeKeepMergeLockHook = func() {}`. This is a test seam this plan adds. An expiry sweep in the seam would be masked by the build's rule 2, so A5 needs a reload there that removed an unexpired entry.
- `ReplaceSecrets`, `PutSecret`, `DeleteSecret` and `SetGlobalAdTag` keep their code. `toConfig`, `forget` and the engine's rule 6 (Task 1) give spec §5.1's table.

- [ ] **Step 1: Failing tests:**
  - `TestPutSecretsKeepsTheEntriesOfTheNamesItKeeps` (A1): a removed name's entries go. The library `ReplaceSecrets` with a nil `Retiring` clears them.
  - `TestPostingTheRetiringKeyBackMakesItPrimary` (A2, the revert): the entry is dropped, the K1 streams stay, the K2 streams close.
  - `TestDeletingASecretDropsItsEntries` (A3).
  - `TestPostingAnotherNameKeepsEveryEntry` (A4).
  - `TestAPutCannotReAddAnEntryAReloadRemoved` (A5): the hook runs a `ReloadSecrets` whose config ends the overlap while `until` is still ahead. The PUT's result holds no K1.
  - `TestReloadReplacesTheEntriesWithTheFiles` (A6).
  - `TestAPanelRekeyIsStillImmediate`: a PUT with a new key closes the old key's streams and creates no entry.
  - `TestThereIsNoRotateRoute` (D18): `POST /secrets/alice/rotate` answers 404. It is a guard, green from the start; its sabotage is below.
  - Run: FAIL.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Sabotage.** Each item makes a named test fail:
  - the PUT drops entries;
  - the PUT keeps a removed name's entries;
  - the merge reads the set before the hook (A5);
  - `PutSecret` turns the old primary into an entry;
  - nil means "keep" in `ReplaceSecrets`;
  - register `POST /secrets/{name}/rotate` in `buildAPIHandler` (the guard fails).

  Restore after each.
- [ ] **Step 4: Gate**, then commit `feat(mtglib): API mutations keep the file's overlaps`.

**Model:** sonnet. It is a small merge, and the tests carry it. **Review:** task review (no revival through a PUT; panel re-key immediate; the revert row).

### Task 7: The read-only view

**Files:**
- Create: `mtglib/proxy_retiring_view.go`
- Modify: `mtglib/proxy_stats.go` (`UserStatsJSON` fields, `secretStats`, `FeatureSecretRotation`, `supportedFeatures`), `mtglib/proxy_api.go` (`SecretInfo` fields, `handleStats` overlay, `SnapshotSecrets`), `mtglib/proxy_serve.go` (`admit` stamps), `mtglib/proxy_stats_features_test.go`: the four pinned lists in `TestStatsFeatures` (lines 46, 114, 135, 154) and its string-assertion block (56–78) are edited deliberately; `TestStatsOmitemptyShapeUnchanged`, in the same file (230–274), is not touched
- Test: `mtglib/proxy_stats_retiring_test.go`

**Interfaces:**
- Produces: on both `UserStatsJSON` and `SecretInfo`:
  - `RetiringKeys int` `json:"retiring_keys,omitempty"`;
  - `RetiringUntil *time.Time` `json:"retiring_until,omitempty"` (UTC);
  - `RetiringConnections int` `json:"retiring_connections,omitempty"`;
  - `RetiringLastSeen *time.Time` `json:"retiring_last_seen,omitempty"`.
- Produces: `secretStats.retiringLastSeen atomic.Int64`, stamped by `admit` when `ctx.retiringUntil` is non-zero.
- Produces: `type retiringView struct{ keys int; until time.Time; connections int; lastSeen time.Time }`.
- Produces: `func (p *Proxy) retiringViews(set *secretSet, now time.Time) map[string]retiringView`.
  - It covers only names with unexpired entries at `now`, which is `p.rotation.Now()`.
  - `connections` counts, under `liveMu` and for those names only, the streams whose `matchedSecretKey` is not the name's current primary.
  - `lastSeen` is reported only while `keys > 0`.
  - It is overlaid onto users that already exist, never adding one, in `handleStats` and `SnapshotSecrets`.
- Produces: `FeatureSecretRotation = "secret-rotation"`.

- [ ] **Step 1: Failing tests:**
  - `TestRetiringFieldsAppearOnlyWhenRelevant` (A7): `/stats` and `GET /secrets/{name}`. Nothing new appears under `users`, and `TestStatsOmitemptyShapeUnchanged` stays untouched and green.
  - `TestRetiringConnectionsCountsLiveOldLinkStreams` (A8): N right after a rotation, when every old-link stream was admitted as the primary.
  - `TestRetiringLastSeenFollowsRetiringAdmissions` (D31).
  - The feature lists and the `IsSorted` assertion (A9).
  - Run: FAIL.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Sabotage.** Each item makes a named test fail:
  - count connections from an admission flag (A8);
  - add a user from the view;
  - report `retiring_last_seen` without keys;
  - insert the feature unsorted.

  Restore after each.
- [ ] **Step 4: Gate**, then commit `feat: the overlap's state in /stats and GET /secrets`.

**Model:** sonnet. These are read-backs. **Review:** task review (shapes unchanged without rotation; nothing under `users`).

### Task 8a: `[[retiring-secret]]` in `internal/config`

**Files:**
- Create: `internal/config/retiring.go`, `internal/config/testdata/panel-rendered.toml` (a copy of `panel_contract_test.go`'s `rendered` text; that test file stays untouched), `internal/config/testdata/panel-config-string.golden`
- Modify: `internal/config/parse.go`, `internal/config/config.go` (`RetiringSecrets`, `ConfigRetiringSecret`, `redactConfigCredentials`), `internal/config/env.go`
- Test: `internal/config/retiring_test.go`, `internal/config/retiring_properties_test.go`, additions to `internal/config/config_test.go` and `env_test.go`

**Interfaces:**
- Produces: the `tomlConfig.RetiringSecrets` field, verbatim from spec §1.1. `Parse` normalises each field before the JSON step:
  - a string is kept;
  - a `time.Time` becomes `time.RFC3339Nano`;
  - anything else becomes `fmt.Sprint(v)` and is recorded as wrong-typed.

  After the JSON decode it sets the mark on `conf.RetiringSecrets[i]`.
- Produces: `type ConfigRetiringSecret struct{ Name string `json:"name"`; Secret string `json:"secret"`; Until string `json:"until"`; wrongType uint8 }`, a bitmask over the three fields. Also `Config.RetiringSecrets []ConfigRetiringSecret` `json:"retiringSecrets,omitempty"`.
- Produces: `type RetiringReport struct{ Usable []mtglib.RetiringSecret; Lines []string; Expired int; Notes []string }`.
- Produces: `func (c *Config) GetRetiringSecrets(now time.Time) RetiringReport`. It is pure, and applies §1.3's table in order:
  - the `name` of `"default"` resolves only when `[secrets]` is empty, as `GetSecrets` does;
  - `secret` is parsed with `mtglib.ParseSecret`, and its error text is discarded;
  - `until` is parsed with `time.Parse(time.RFC3339Nano, …)`;
  - rule 5's population is every entry that passes rule 1, plus every primary;
  - the problem and rule-4 lines are §1.3's wording verbatim;
  - the Notes are `retiring-secret #<n> (name "<name>"): the key is the secret's own primary; the entry changes nothing` (rule 6) and `retiring-secret #<n> (name "<name>"): the same key as another entry of this name; the later until is kept` (rule 7);
  - `Usable` is in file order.

  `Validate()` does not call it.
- Produces: `applyEnvSecret` also sets `c.RetiringSecrets = nil`. `redactConfigCredentials` replaces `retiringSecrets[*].secret` with `[redacted]`.

- [ ] **Step 0:** Before any edit, render `testdata/panel-rendered.toml` with `config.Parse(…)` and `Config.String()` on the unmodified code, and commit nothing yet: write the output to `testdata/panel-config-string.golden`. It is captured once, here, and never regenerated.
- [ ] **Step 1: Failing tests:**
  - C1 `TestEveryRetiringRuleClassifies`: one case per row, as a problem, a warning or inert, with value-free messages. One row is an **expired block whose name is no longer in `[secrets]`**: inert, no line (rule 3 looks only at unexpired entries).
  - C2 `TestUntilSpellings`.
  - C3 `TestWrongTypesAreProblemsNotParseFailures`.
  - C4 `TestValidateIgnoresRetiringEntries`.
  - C6 `TestTheSecretEnvironmentClearsRetiringEntries`.
  - C7: `TestConfigStringRedactsEveryCredential` gains an entry, plus `TestConfigStringIsUnchangedWithoutTheTable`, which renders `testdata/panel-rendered.toml` with `Config.String()` and compares it byte for byte with Step 0's golden.
  - C9 `TestCheckAcceptanceIsMonotoneInTime`: a seeded `math/rand/v2` generator over small pools of names, keys and `until`s, with `t < t′`; "accepted" means `GetRetiringSecrets(t).Lines` is empty and there are no unknown keys.
  - C11 `TestAnUnknownFieldInTheBlockIsAnUnknownKey`.
  - C12 `TestRunNeverAcceptsAKeyItDropped`: the same generator. A key absent from `Usable` at `t` is absent at every `t′`.
  - C13 `TestAnOverLongUntilIsWarnedNotDropped`.
  - C14 `TestACrossNameCollisionStaysDroppedAfterOneExpires`.
  - The C8 config slice, `TestConfigLinesNeverCarryTheValue`. None of the four spellings appears in any of these:
    - any line or note;
    - the scalar-shape `Parse` error's `Error()`;
    - `Config.String()`.
  - Run: FAIL.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Sabotage.** Each item makes the named test fail:
  - echo `Secret.Set`'s text in a problem line (C1, C8 slice);
  - apply rule 3 to expired entries (C1's expired-dangling row);
  - judge rule 5 against unexpired entries only (C14);
  - drop a rule-4 entry (C12, C13);
  - a time-dependent rule-8 tie-break (C12);
  - ignore the per-name cap (C1);
  - skip the env clear (C6);
  - leave the value unredacted (C7);
  - add a non-`omitempty` field to `Config` (C7's golden);
  - let `Validate` call `GetRetiringSecrets` (C4).

  Restore after each.
- [ ] **Step 4: Gate** (`./internal/config/`), then commit `feat(config): [[retiring-secret]], judged without ever blocking a load`.

**Model:** opus. P1, P2 and the value-free messages are where R0 is won or lost. **Review:** extra scrutiny (P1 and P2 per rule; `Validate` untouched; no field/method clash; the golden captured before the change).

### Task 8b: `run`, `--check`, `doctor` and the reloader read the table

**Files:**
- Modify: `internal/cli/run.go` (`checkConfig`), `internal/cli/doctor.go`, `internal/cli/run_proxy.go` (the start-up report, the reloader)
- Test: `internal/cli/run_check_retiring_test.go`, `internal/cli/doctor_retiring_test.go`, `internal/cli/run_proxy_rotation_clock_test.go`, `internal/cli/reload_retiring_test.go`

**Interfaces:**
- Consumes: Task 8a's `GetRetiringSecrets`, Task 2's `runProxyWith(…, now)`, `makeSecretsReloader(path, logger, clock)`.
- Produces: `checkConfig(conf *config.Config, now time.Time) error` refuses on unknown keys or any `report.Lines`, with `errRetiringProblems` listing them. `Run` passes `time.Now()`. A refused parse is printed in its `Error()` form only.
- Produces: `func (d *Doctor) checkRetiringSecrets() bool`. It joins `diagnose`'s conjunction. Any line fails it. The expired count is shown with the `--prune` hint and does not fail.
- Produces: in `runProxyWith`, `report := conf.GetRetiringSecrets(clock.Now())` sets `opts.RetiringSecrets = report.Usable`. The reloader computes the report on every reload on the **same** clock and sets `Retiring: report.Usable`. Both log:
  - each line at Warning, in `warnUnknownKeys`' style;
  - the expired count at Info as `retiring-secret entries past their until are ignored; rotate-secret --prune removes them`, with `expired`;
  - the Notes at Info.

- [ ] **Step 1: Failing tests:**
  - C5 `TestRunCheckRefusesProblemsAndAcceptsInertEntries`, including an expired block whose name is no longer in `[secrets]`, which `--check` accepts. The refusal carries none of the four spellings.
  - C10 `TestThePanelsConfigHasNoRetiringLines`: `checkConfig` over the panel's text (the 8a testdata copy) refuses nothing.
  - C15 `TestTheTablesShapes`:
    - a single `[retiring-secret]` is one usable entry with no unknown key;
    - `retiring-secret = "x"` fails `Parse`, `run` does not start, and a reload through `makeSecretsReloader` keeps the previous set;
    - `run --check` prints only the `Error()` form, and that form carries no value.
  - C16 `TestDoctorFailsOnARetiringLineButNotOnExpiredEntries`; the doctor's output carries no spelling.
  - `TestAReloadWithABadBlockAppliesTheRest` (D4, §10): `makeSecretsReloader` over a file that re-keys `[secrets]` and carries one block with a malformed `until` returns the new primary, no entry for that block, a Warning line, and no error.
  - E6 `TestOneRotationClockServesTheReloaderAndTheProxy`. It is serial and pipes `os.Stdout` like `TestRunLoopWarnsAboutPerAddressControlsBehindProxyProtocol`. Its setup:
    - the config is the loop harness's (its hostless dd secret, so no start-up DNS lookup), plus `debug = true` and `api-bind-to` on a loopback port the test reserved;
    - it holds a dd `[[retiring-secret]]` for `default` with `until` U;
    - the fake `now` reads U+1h when `runProxyWith` starts and U−1h before a `POST /reload`; it is read through an `atomic.Int64`, because the API handler's goroutine reads it;
    - the test restores zerolog's global level in `t.Cleanup`.

    It asserts:
    - the reload's Info summary counts the entry as expired;
    - no `a retiring key was ignored` line with `reason=expired` appears;
    - one behind Warning carries `behind_by`.
  - Run: FAIL.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Sabotage.** Each item makes the named test fail:
  - make a problem refuse the load under `run` (`TestAReloadWithABadBlockAppliesTheRest`);
  - let `checkConfig` ignore `report.Lines` (C5);
  - leave the retiring check out of `diagnose`'s conjunction (C16);
  - build a second clock for the reloader in `runProxyWith` (E6);
  - print `DecodeError.String()` in `--check` (C15).

  Restore after each.
- [ ] **Step 4: Gate** (`./internal/cli/ ./internal/config/`), then commit `feat: run, --check, doctor and reload read [[retiring-secret]] on the rotation clock`.

**Model:** opus. E6 is the only test that sees `runProxyWith`'s own wiring, and the bad-block reload is D4. **Review:** extra scrutiny (one clock instance; the reload applies the rest; `Error()`-only output).

### Task 9a: `rotate-secret`'s edit — pure functions over bytes

**Files:**
- Create: `internal/rotation/rotation.go` (`Request`, `Prepare`, `Prepared`), `internal/rotation/locate.go` (the `unstable` locator), `internal/rotation/splice.go`, `internal/rotation/verify.go`
- Test: `internal/rotation/rotation_test.go`, `internal/rotation/testdata/<case>.toml` and `<case>.golden`

**Interfaces:**
- Produces: `type Request struct{ Name string; Rotate bool; Until time.Time; EndOverlap, Prune bool; Now time.Time }`. A `Rotate` with a zero `Until` is `--overlap 0` and adds no block. `Now` is the run's one fixed instant; expiry for `--prune` means `until ≤ Now`.
- Produces: `func Prepare(doc []byte, req Request) (*Prepared, error)`. This is step 1 of spec §7.3:
  - it refuses a file that `config.Parse` refuses, or that `Validate` fails, with the parser error's `Error()` form only. That covers the scalar shape and a BOM;
  - it refuses an unknown name, a multi-line string, a 5th unexpired entry for the name, and `"default"` while `[secrets]` is present (§7.1 wording);
  - it locates the primary's string node and every block;
  - problems and warnings the file **already** has do not refuse it (§7.3 step 1: an urgent rotation is not blocked); `func (p *Prepared) Warnings() []string` returns them, value-free, for 9b's stderr. Only lines the edit would add refuse (step 5).

  Nothing is generated here.
- Produces: `func (p *Prepared) Primary() mtglib.Secret` and `func (p *Prepared) Summary() Summary`, where `type Summary struct{ Name string; Until time.Time; Removed []Removed; NoOp bool }` and `type Removed struct{ Name string; Until string }`. A Summary never holds a value.
- Produces: `func (p *Prepared) Apply(newPrimary mtglib.Secret) ([]byte, error)`, which is steps 2–5:
  - it splices the new value in the old text's encoding (hex when the old text decodes as hex, base64url otherwise) and quote style (basic or literal);
  - it inserts a block before the `[secrets]` header and the run of comment lines directly above it, or at the end of the file when there is no header. The block is `[[retiring-secret]]`, then `# added by mtg-proxy rotate-secret at <Now, RFC 3339 Z>`, then `name`, `secret` (the old text) and `until`, as in the §1.1 example, with line endings following the file;
  - it removes blocks of both header kinds (§7.3 step 4), walking back over the comment lines that head the next table;
  - it verifies by re-parse, as step 5 says: `reflect.DeepEqual` on everything but the two fields, and no new lines from `GetRetiringSecrets(Now)`;
  - any difference returns `ErrEditVerification` (`internal error: the edit changed more than it meant to; nothing was written`);
  - with `Rotate` false (`--end-overlap`, or `--prune` alone) `Apply` ignores `newPrimary` and splices no value, and the verification then requires the name's primary to be unchanged.
- Produces: `var spliceHook = func(b []byte) []byte { return b }`, applied before verification, for R2.
- The locator, per §7.3 "What the parser gives":
  - it uses `unstable.Parser{KeepComments: true}`;
  - a key's path is the current table's path plus the dotted key, so quoted, dotted and inline forms all resolve;
  - a header is found from its first key node's `Raw`, scanning back to the `[` or `[[` that opens the line. It never indexes the header node's own `Raw`.

- [ ] **Step 1: Failing tests:**
  - R1 `TestRotateTheCorpus`, with one subtest per layout compared against its golden file under a fixed `newPrimary` and `Now`, each also passing the re-parse diff:
    - `example`, which is a **copy** of `example.config.toml` with a live `[secrets]`, placed in `testdata`. Never the live file: Task 12 edits it;
    - `panel-quoted-keys`;
    - `dotted-secrets`;
    - `inline-secrets`;
    - `single-secret`;
    - `crlf`, built in the test from the LF fixture, with its golden converted the same way;
    - `no-final-newline`;
    - `comments-above-secrets`;
    - `existing-blocks`;
    - `single-table-typo-block`.

    A BOM file and the scalar shape are refused, and the refusal carries no value.
  - R2 `TestABadSpliceIsCaught`: `spliceHook` corrupts the splice and `Apply` returns `ErrEditVerification`. A second case moves the block inside `[secrets]`, which the `UnknownKeys` difference catches.
  - R3 `TestRemovalKeepsTheNextTablesHeadingComment`: a comment inside a removed block goes with it.
  - `TestTheNewValueKeepsTheOldEncodingAndQuoteStyle`.
  - `TestPrepareRefuses`, the pure half of R9.
  - `TestExistingProblemsDoNotBlockARotation`: a file that already carries a problem block rotates; `Warnings()` holds its value-free line.
  - `TestEndOverlapAndPruneLeaveThePrimaryAlone`: `Apply` with `Rotate` false changes no primary byte, and a sabotaged splice of the primary is caught by the verification.
  - `TestTheSummaryCarriesNoValue`, the pure half of R8.
  - Run: FAIL.
- [ ] **Step 2: Implement.** Use no filesystem in this task.
- [ ] **Step 3: Sabotage.** Each item makes a named test fail:
  - index the header node's own `Raw`;
  - insert after the `[secrets]` header;
  - skip the verification;
  - compare only `Secrets` in it;
  - drop the comment walk-back;
  - write LF into a CRLF file;
  - write base64 for a hex file;
  - refuse on an existing problem line (the existing-problems test);
  - require "primary equals `newPrimary`" when `Rotate` is false (the end-overlap test).

  Restore after each.
- [ ] **Step 4: Gate** (`./internal/rotation/`), then commit `feat: rotate-secret's file edit, pure and verified by re-parse`.

**Model:** opus. The spec names this as where the subtle bugs will be. **Review:** extra scrutiny (the corpus; verification cannot be bypassed; no filesystem).

### Task 9b: `rotate-secret` — the command and its I/O

**Files:**
- Create: `internal/cli/rotate_secret.go`, `internal/cli/rotate_secret_write.go`, `internal/cli/rotate_secret_unix.go` (first line `//go:build !windows`, as in `reload_signal.go`: `_unix` is not a file-name constraint, and without the tag it compiles on Windows beside the next file) and `rotate_secret_windows.go` (owner and directory fsync)
- Modify: `internal/cli/cli.go`
- Test: `internal/cli/rotate_secret_test.go`, `internal/cli/rotate_secret_unix_test.go` (first line `//go:build !windows`)

**Interfaces:**
- Produces: `type RotateSecret struct{ ConfigPath string; Name string; Overlap string; Host string; EndOverlap, Prune, DryRun, Reload, Force bool; out, errOut io.Writer; now func() time.Time }`, with these kong tags:
  - `config-path` is a required `existingfile` argument;
  - `name` is an optional argument;
  - an `Overlap` of `""` means not given.

  Also `func (r *RotateSecret) Run(cli *CLI, version string) error`. `CLI` gains `RotateSecret RotateSecret` with `kong:"cmd,name='rotate-secret',help='…'"`.
- The flow, from spec §7:
  1. Check the flags and give the §7.1 refusals in their wording. Without `--overlap` the message is `say how long the previous key stays accepted: --overlap 24h, or --overlap 0 to retire it at once`. Also refuse an overlap over 720h, `--host` with dd or plain, and `default` with `[secrets]`.
  2. Apply the panel heuristic (§7.6) unless `--force`.
  3. Resolve the target with `filepath.EvalSymlinks`.
  4. Run the writable checks.
  5. Take the `O_EXCL` lock, which holds the pid and the start time. An existing lock is refused with the remedy text, and the lock is removed on exit.
  6. Read the file and call `rotation.Prepare`, and print its `Warnings()` (the file's existing, value-free problem lines) to stderr as warnings.
  7. With `--dry-run`, print the summary to stderr and stop.
  8. Generate the new key with `generateSecret(mode, host)`, which is `mtglib.GenerateSecretMode` behind a package var.
  9. Call `Apply`.
  10. Re-read the target and abort on a SHA-256 mismatch (`the file changed while rotating; nothing was written`).
  11. Write atomically, as in §7.4 step 5.
  12. Print stderr per §7.2, and stdout exactly one line, the new value.

  A no-op exits 0 and says so (§7.7).
- Produces: `var renameFile = os.Rename`. With `EBUSY` or `EXDEV`, the run gives the §7.4 mount-point message, writes nothing, and removes the temp file.

- [ ] **Step 1: Failing tests:**
  - R4: the lock refuses a concurrent run, naming the lock file and the remedy; a changed file aborts before the rename.
  - R5: a non-writable file is refused. On Unix, mode bits are preserved and the owner check runs. A symlink's target is written; the test skips on Windows when `os.Symlink` fails.
  - R6: the `EBUSY` seam leaves the file and the directory listing byte-identical before and after, and no other file holds the old content after any run, successful or not.
  - R7, the stderr half: stdout is exactly one line. Stderr, across success, dry-run, the lock refusal, the hash abort and the scalar-shape refusal, holds none of the four spellings of the old value.
  - R8: `--dry-run` leaves the file and the listing unchanged, and `generateSecret` is called 0 times.
  - R9: each refusal, including a 5th entry.
  - R11: a `…/mtproto/mtg-7.toml` path is refused, and `--force` passes.
  - `TestOverlapZeroWritesNoBlock`.
  - `TestAWebEnabledFileSaysWebLinksChangeNow`.
  - `TestANoOpExitsZeroAndSaysSo` (§7.7): `--prune` with nothing to prune, and `--end-overlap` for a name without blocks, exit 0, write nothing, and say so on stderr.
  - `TestTheNewKeyKeepsTheModeAndHost` (D22, §7.2): `generateSecret` receives the old primary's mode and host, or the `--host` value for ee.
  - `TestExistingProblemsAreWarnedNotBlocking` (§7.3 step 1): a file that already has a problem line still rotates, and stderr carries the value-free line.
  - Run: FAIL.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Sabotage.** Each item makes a named test fail:
  - write through the existing inode (R6);
  - leave the temp file on failure (R6);
  - print the old value in a refusal (R7);
  - skip the hash check (R4);
  - break a stale lock (R4);
  - skip `Chmod` (R5 on Unix);
  - generate with a fixed mode, or ignore `--host` (the mode-and-host test);
  - exit non-zero on a no-op (the no-op test).

  Restore after each. The Unix-only tests run once on the bench box in Task 13's session; otherwise they are recorded as unverified.
- [ ] **Step 4: Gate**, then commit `feat: mtg-proxy rotate-secret`.

**Model:** opus. File safety and the never-print rule are security properties. **Review:** extra scrutiny (never prints the old value; never leaves a copy of the old file; the temp file is always removed).

### Task 10: `rotate-secret --reload`, and the whole leak sweep

**Files:**
- Create: `internal/cli/rotate_secret_reload.go`
- Modify: `internal/cli/rotate_secret.go`
- Test: `internal/cli/rotate_secret_reload_test.go`, `internal/cli/rotation_leak_sweep_test.go`

**Interfaces:**
- Produces: `type reloadTarget struct{ base, token string; client *http.Client }` and `func reloadTargetOf(conf *config.Config) (reloadTarget, error)`. A missing `api-bind-to` is refused before anything is written. A host of `0.0.0.0` becomes `127.0.0.1`, and `::` becomes `::1`.
- Produces: `func (t reloadTarget) preCheck(ctx context.Context, force bool) error`, which does `GET /stats` and nothing else. Its outcomes:
  - an unreachable API is refused;
  - if `features` lacks `secret-rotation`, it is refused unless `force`.
- Produces: `func (t reloadTarget) reloadAndCheck(ctx context.Context, written []byte, names []string, newUntil time.Time, now time.Time) error`.
  - It sends `POST /reload`, which must answer 200. On failure it prints only the status line.
  - Then it sends `GET /secrets/{name}` for each touched name. Every expected value comes from `written`, parsed with `config.Parse` and judged with `GetRetiringSecrets(now)`.
  - Check 1 compares the parsed primary, meaning key, mode and host.
  - Check 2 compares `retiring_keys` with the name's usable count, where absent means 0.
  - Check 3 requires `retiring_until ≥ newUntil` when a block was added.
  - A failure gives `the file is rotated but the proxy does not serve it: <check> differs (<expected> vs <reported>); likely: <causes>`, using §7.5's causes per check.
  - With `--prune` alone, it checks the 200 and then check 2 for each pruned name still configured.
  - The file is never rolled back.

- [ ] **Step 1: Failing tests:**
  - R10, one subtest per bullet of the spec.
    - Most run against `runProxyWith` through the loop harness (`runInBackground`, with the harness's hostless dd secret and `api-bind-to` on a reserved loopback port), which supplies the shared clock and the real reloader (Task 8b); a hand-built `NewProxy` would need a Network, a cache, two lists and an event stream. A test that reads stdout is serial, and one that sets `debug = true` restores zerolog's global level in `t.Cleanup`.
    - An `httptest` stub covers three bullets: the missing feature, a 500 whose body contains the old value, and the unreachable API.
    - The bullets include a second rotation inside a longer earlier overlap, which passes with `retiring_keys` 2.
    - They include `--overlap 0` and `--end-overlap`.
    - They include `--end-overlap` after a rotation written without `--reload`, which passes check 1.
    - They include `--prune` alone, and the refusal before writing when the API is unreachable, after which the file is unchanged.
  - `TestAFailedReloadPrintsOnlyTheStatusLine` (R7's reload half).
  - C8 `TestNoSpellingOfTheRetiringValueEverAppears` runs a scripted rotation end to end and collects every log line, error, stdout and stderr line, and HTTP body. Neither the four spellings of the retiring value nor its key may appear anywhere. The script:
    - `rotate-secret --reload` with `debug = true`;
    - the API reads;
    - problem lines;
    - a refused scalar-shape reload, through `run --check`, `POST /reload` and `rotate-secret`;
    - the 500 bodies;
    - `access` over the rotated file (§6.1 names it; it prints primaries only).
  - Run: FAIL.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Sabotage.** Each item makes the named test fail:
  - require `retiring_until` to equal the written `until` (the second-rotation case);
  - take check 1's expected value from the proxy's earlier state (the m5′ case);
  - print the reload body (R7);
  - write before the pre-check (the unreachable case);
  - roll the file back on failure;
  - log `report.Usable` with `%v` at Debug in the reloader (C8: `Secret.String()` is the value).

  Restore after each.
- [ ] **Step 4: Gate**, then commit `feat: rotate-secret --reload reloads the proxy and reads the rotation back`.

**Model:** opus. It owns the whole D21 leak sweep, the m5′ cases and a real-proxy harness in `internal/cli`. **Review:** extra scrutiny (refusal before writing; never rolls back; M1's second-rotation case; m5′'s two cases; every surface in the C8 script).

### Task 11: The WEB relay recognises retired capabilities

**Files:**
- Modify: `internal/webrelay/capability.go`, `internal/webrelay/origin.go`, `internal/config/retiring.go` (`RetiringValues`), `internal/cli/run_web_relay.go`, `internal/cli/web_relay_watch.go`
- Test: `internal/webrelay/capability_retired_test.go`, `internal/cli/web_relay_watch_retired_test.go`

**Interfaces:**
- Produces: `func NewRegistryWithRetired(host string, secrets, retired []mtglib.Secret) (*Registry, error)`.
  - Retired capabilities are derived from `WebSecret(s)`, up to `MaxProfiles`.
  - A retired capability equal to a live one is dropped.
  - `NewRegistry(host, secrets)` is the same function with nil.
  - It never returns an error because of the retired list: `RetiringValues` can hold duplicates (a rule-5 or rule-7 file) and more than 4,096 values, and an inert file must not refuse the relay's start or reload. Duplicates within the list are dropped, values past 4,096 are left out, and a value whose `Derive` fails is skipped. Only the live list keeps `NewRegistry`'s errors.
- Produces: `IsAuthentic` scans the live list and then the retired list, constant-time and never breaking. It goes through `func (r *Registry) authentic(param string) (bool, int)`, which also returns the count of compares made, for W5. `Lookup` stays live-only.
- Produces: `func (c *Config) RetiringValues() []mtglib.Secret`. It returns the values that pass §1.3 rule 1, whatever their name or time. It returns nil after the `SECRET` override.
- Produces: `OriginOptions.Retired []mtglib.Secret` and `func (o *Origin) SetSecretsWithRetired(secrets, retired []mtglib.Secret) error`. `SetSecrets(secrets)` keeps its signature as the nil form, so its five test callers stay unchanged. This is the spec's "`Origin.SetSecrets` gains the list".
- Produces: `profileReloader.apply` compares the retired list as well as the profiles. A retired-only change calls `SetSecretsWithRetired`, keeps `r.current`, counts no profile reload, and logs at Debug.

- [ ] **Step 1: Failing tests:**
  - W1: a retired capability, expired or not, gets the local 404 and never reaches a recording cover upstream.
  - W2: it never serves the bridge.
  - W3: a retired-only file change leaves the profiles and the reload count unchanged, but the new retired capability is recognised.
  - W4: a collision keeps the live capability.
  - W5: with 4,096 live and 4,096 retired capabilities, `authentic` reports 8,192 compares for a first match, a last match and no match.
  - `TestRetiringValuesFollowRuleOneOnly`.
  - `TestAnInertRetiredListNeverRefusesTheRelay`: a retired list with duplicates, with 4,097 values, and with a value equal to a live one builds a registry without error.
  - Run: FAIL.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Sabotage.** Each item makes the named test fail:
  - `Lookup` a retired capability (W2);
  - break early (W5);
  - skip the retired compare on reload (W3);
  - keep a colliding retired capability (W4);
  - pass the retired list through `NewRegistry`'s collision and size checks (the inert-list test).

  Restore after each.
- [ ] **Step 4: Gate** (`./internal/webrelay/ ./internal/cli/`), then commit `feat(webrelay): a retired WEB capability is answered locally, never by the cover site`.

**Model:** sonnet. It extends an existing constant-time scan. **Review:** task review (constant time; never `Lookup`; the retired list never errors; W5's count).

### Task 12: Documentation

**Files:**
- Modify:
  - `example.config.toml`: a commented `[[retiring-secret]]` block before `# [secrets]`, with the placement rule and the CLI;
  - `docs/wiki/Configuration.md`;
  - `docs/wiki/Security.md`;
  - `docs/wiki/Monitoring.md`;
  - `docs/wiki/Multi-User-and-API.md`;
  - `docs/wiki/WEB-Proxy-Setup.md`;
  - `docs/wiki/Installation.md`;
  - `docs/wiki/FAQ.md`;
  - `docs/wiki/Home.md`;
  - `README.md`;
  - `SECURITY.md`.

- [ ] **Step 1:** Write each passage listed under the spec's "Docs to update". Re-read each one against the code, never against the spec alone. Every passage must also cover:
  - D27: `run` has no SIGHUP handler, and a SIGHUP ends it;
  - D30: an older binary ignores the table, `--check` on it refuses the file, and `--reload` checks the feature;
  - rotation is unsupported on panel-managed files;
  - a config on NFS is not protected against two concurrent runs;
  - a crashed run leaves a `.tmp` and a lock to delete;
  - the 8,192-compare bound;
  - the one blocking shape (§1.1);
  - a mode change is a hand edit, with an example.

  `SECURITY.md` replaces its "not supported" wording, if it has any, with the overlap-as-grant summary and a pointer to `docs/wiki/Security.md`.
- [ ] **Step 2:** Draft the release-notes text into `task-12-report.md`; Task 14 copies it into `final-report.md`. It names the feature and the `key_revoked` refusal that reaches every deployment, with its log line and the race it closes. It is not a CHANGELOG file.
- [ ] **Step 3:** Commit `docs: secret rotation with an overlap period`.

**Model:** sonnet. **Review:** task review. Every claim must match the code, including the exact log messages, field names and flags.

### Task 13: Benchmarks and the box A/B (controller runs the box)

**Files:**
- Modify: `mtglib/door_bench_test.go` (a new top-level `BenchmarkDoorHandshakeRetiring`; `BenchmarkDoorHandshake` is not touched)
- Create: `mtglib/secret_rotation_bench_test.go`, `benchmarks/results/2026-10-08-secret-rotation-ab.txt`, `benchmarks/results/2026-10-08-secret-rotation-report.md`

- [ ] **Step 1:** Write the benchmark rows. Each one verifies the outcome it measures.
  - The new rows are `BenchmarkDoorHandshakeRetiring/<ee-unpaced|dd>/secrets=<N>/retiring=<1|100>/old`, a top-level function of their own, with a client on a retiring key, plus `…/old/hinted` for ee-unpaced only (the obfuscated door has no hints, as in the existing rows). Under `BenchmarkDoorHandshake` any selector for the existing rows would also run them, because Go matches a `-bench` pattern level by level and a shorter pattern runs every deeper row.
  - `BenchmarkBuildSecretSetAt` has `secrets=5000/retiring=<0|100|4096>`.
  - `BenchmarkCloseStaleConns` has 10,000 live streams, for `rotation` and for `unrelated`.
  - The existing rows keep their names. Run each once locally with a tiny `-benchtime`.
  - Commit `bench: secret rotation rows`.
- [ ] **Step 2 (controller):**
  1. Cross-compile the `mtglib` test binary for the branch base (`8577930`) and for the branch head. Build the base from a separate worktree: `git worktree add <scratch> 8577930`, then `go -C <scratch> test -c -o <out> ./mtglib/` (env-prefixed, so through the Bash tool; the sandbox refuses `cd`), then `git worktree remove <scratch>`. Never check out, stash or reset in `handshake-scale`.
  2. On the box, under its rules, alternate old and new at least 10 times each on the existing rows: every `BenchmarkDoorHandshake/(ee-unpaced|dd)` row (`secrets=1/100/1000/5000`, `first/last`, ee's `last/hinted`) and `BenchmarkScanBudgetReserve`. `BenchmarkVerify` lives in `mtglib/internal/tls/fake`, a package this branch must not change, so it is not run.
  3. Run the new rows (`BenchmarkDoorHandshakeRetiring`, `BenchmarkBuildSecretSetAt`, `BenchmarkCloseStaleConns`) on the new binary only.
  4. Compare with `benchstat` (the scratchpad copy; see Global Constraints, Tools).

  In the same session, run the Unix-only `internal/cli` and `internal/rotation` tests, cross-compiled, without `-race`. Record what passed. Delete `/root/mtg-bench` at the end.
- [ ] **Step 3: The bar.** On the no-retiring rows there must be no significant regression above 3% at p < 0.05, and allocs/op show no significant change (benchstat `~`; these whole-connection rows vary by a few allocs from run to run, so exact identity is pinned by Tasks 3 and 4's `AllocsPerRun` tests instead). The new rows are reported against the spec's expectations: unhinted ≈ a `last` row at N+R, hinted ≈ 2 verifications. If a no-retiring row misses the bar, stop: the split-loop design (§3.1) is revisited before anything else changes. Commit `bench: secret rotation, before and after`.

**Model:** sonnet writes the rows; the controller runs the box. **Review:** task review. Every row must verify what it measures, and the A/B must be same-session.

### Task 14: Whole-branch gate, final review, report (controller)

- [ ] **Step 1: Gate:**
  - run `golangci-lint config verify`, then `golangci-lint run`;
  - run `go build ./...` and `go vet ./...`;
  - run `go test -count=2 -race ./...` once;
  - run `govulncheck ./...` (the scratchpad copy; see Global Constraints, Tools — if it cannot run, the report says so);
  - `git diff 8577930 -- mtglib/proxy_golden_faketls_test.go mtglib/internal/tls/fake internal/config/panel_contract_test.go internal/testclient` must print nothing;
  - `git diff 8577930 -- mtglib/proxy_stats_features_test.go` shows hunks inside `TestStatsFeatures` only, never in `TestStatsOmitemptyShapeUnchanged` or `TestStatsResponseShapeUnchanged`.

  Do not claim CI.
- [ ] **Step 2: Final review.** An independent reviewer on the most capable model reviews the whole branch against the spec, the Review Focus, both spec reviews and the plan's pre-flight review (`plan-review.md`). Each finding is fixed test-first, with its own sabotage. Then re-run the gate.
- [ ] **Step 3: Report.** Write `.superpowers/sdd/2026-10-08-secret-rotation/final-report.md`. It includes:
  - the per-task sabotage logs;
  - Task 0's lists;
  - the bench outcome;
  - the Unix-only coverage;
  - the release notes, copied from `task-12-report.md`;
  - the honest limits: the restart clock gap, single-file bind mounts not tried, and the 2-vCPU box.

  Commit it with the results, if the reports are tracked. Never push, tag or merge.

**Model:** opus for the final review (fable when available). **Review:** this task is the review.

---

## Self-review

**Spec coverage, D1–D32:**

| D | Task(s) | D | Task(s) |
|---|---|---|---|
| D1 file is the only source | 6 (no write route), 8a, 9b | D17 mutations keep entries | 6 |
| D2 `[[retiring-secret]]` | 8a, 8b (C15), 9a | D18 no rotate route | 6 (`TestThereIsNoRotateRoute`, a guard with its own sabotage) |
| D3 RFC 3339 with offset | 8a (C2), 9a | D19 four scalars, feature | 7 |
| D4 problems never block | 8a (C1), 8b (C5, `TestAReloadWithABadBlockAppliesTheRest`), 9a (`TestExistingProblemsDoNotBlockARotation`), 9b | D20 read-time connections | 7 (A8) |
| D5 P1 / P2 | 8a (C9, C12–C14) | D21 never printed | 2, 5, 8a, 8b, 9b, 10 (C8, with `access`) |
| D6 caps, 720 h | 1 (rule 8; the engine never applies rule 4), 8a (rules 4, 8), 9a/9b (R9) | D22 `rotate-secret`, keeps mode | 9a, 9b (`TestTheNewKeyKeepsTheModeAndHost`) |
| D7 any mode and host | 1 (hosts), 3 (D7), 4 (D5, D6) | D23 surgical edit, re-parse | 9a |
| D8 primary wins | 1 (rules 5, 6), 8a | D24 atomic write | 9b (R5, R6) |
| D9 retiring after primaries | 1 (E1, E2, `primaryEnd`), 3 (D3) | D25 panel heuristic | 9b (R11) |
| D10 one high-water clock | 2 (E5), 8b (E6) | D26 `--reload` | 10 |
| D11 exact at admission, 5 s close | 3 (D2), 4 (D5), 5 (L2, L2b, L9) | D27 no SIGHUP | 12 (docs; no handler added) |
| D12 hinted primary then retiring, 32 | 3 (D4, D4b) | D28 WEB relay | 11 |
| D13 budget unchanged | 3 (budget test), 13 | D29 env clears | 8a (C6) |
| D14 matched key travels | 3 (D1), 4 (D5) | D30 downgrade | 10 (feature pre-check), 12 |
| D15 per stream, held-key fast path | 1 (`sameHeldKeys`), 5 (L1–L4, L6) | D31 `retiring_last_seen` | 7 |
| D16 re-check inside `liveMu` | 0 (L5, L5b re-key, the unrelated-swap test), 5 (L5, L5b expiry, the no-swap test) | D32 `--overlap` required | 9b (R9) |

Spec items outside D1–D32 that the pre-flight review found without a test, now owned: a reload with one bad block applies the rest (8b); a no-op exits 0 and says so, §7.7 (9b); the new key keeps mode and host, D22 (9b); existing problems do not block a rotation, §7.3 step 1 (9a, 9b); `access` in the leak sweep, §6.1 (10); the engine never applies rule 4, §2.1 (1).

**Tests:**
- E1–E4 are in 1, E5 in 2 and E6 in 8b.
- D1–D4b and D7 are in 3; D5 and D6 in 4.
- L1–L9 are in 5, except L5/L5b's re-key variants and L7's second half, which are in 0.
- A1–A6 are in 6 and A7–A9 in 7.
- C1–C4, C6, C7, C9, C11–C14 are in 8a; C5, C10, C15, C16 in 8b. C8 is split: its config slice is in 8a, `--check` and doctor output in 8b, its stderr slice in 9b (R7), and the whole sweep in 10.
- R1–R3 are in 9a; R4–R9 and R11 in 9b (R8/R9's pure halves are in 9a); R10 in 10.
- W1–W5 are in 11.
- Every item of the §12 sabotage list appears in the owning task's sabotage step, and every new test of this plan has a sabotage (the D18 guard's is registering the route).

**Step scan:** every task has Files, Interfaces, failing tests with names and assertions, a sabotage list, a gate and a commit message. Bodies are given only where the signature and tests do not determine them: the re-check's placement and its parentheses, the clock's episode rule, `primaryEnd()`, the obfuscated key list (§3.2 verbatim), the expiry sweep (§4.2 verbatim), and the splice and verification steps (§7.3). Exact allocation identity is pinned by `AllocsPerRun` tests, never by a single bench run.

**Names across tasks:**
- `accepts` (0, extended in 1); `secretMatch`, `primaryMatch`, `matchAt`, `retiringMatch`, `primaryEnd` (1 → 3, 4).
- `sameHeldKeys` (1 → 5); `RotationClock` and `Proxy.rotation` (2 → 3, 4, 5, 7); `logRetiringDrops` (2); `attributeMatch`, `retiringUntil` and `helloNow` (3 → 4, 5, 7); the methods `(*Proxy).verifyHinted`, `scanCandidates`, `hintedPositions` (3).
- `afterSecretStoreHook`, `staleSkipHook`, `logRetiringChanges` and `closeStaleConns(old, new, now) map[string]int` (5); `beforeKeepMergeLockHook` (6).
- `ConfigRetiringSecret`, `RetiringReport` and `GetRetiringSecrets` (8a → 8b, 9a, 10); `RetiringValues` (11); `rotation.Prepare`, `Prepared.Warnings`, `Apply` and `Summary` (9a → 9b, 10); `checkConfig(conf, now)` (8b).
- `runProxyWith(…, now)` and `makeSecretsReloader(path, logger, clock)` (2 → 8b, 10).
- `BenchmarkDoorHandshakeRetiring`, `BenchmarkBuildSecretSetAt`, `BenchmarkCloseStaleConns` (13); `TestTheFakeTLSDoorAllocatesAsBefore` (3), `TestTheObfuscatedKeyListAllocatesAsBefore` (4).

**Proportion:** about 925 short lines and 96 KB after the pre-flight corrections, against the spec's 2,061 lines and 140 KB — under the spec's size. The reasoning stays in the spec.
