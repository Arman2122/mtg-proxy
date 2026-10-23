# ee handshake at thousands of secrets — before and after

Piece A of the shared-secret program. Spec: `docs/superpowers/specs/2026-10-07-ee-handshake-at-scale-design.md`.
Raw data: `2026-10-07-handshake-scale-baseline.txt` (before) and `2026-10-07-handshake-scale-after.txt` (after).
Box: 5.75.199.10, Intel Xeon Skylake **without SHA-NI**, **2 vCPU**, loopback, `GOMAXPROCS=2`, run on the bench box
under its rules (work dir `/root/mtg-bench`, removed afterwards). `benchstat` for every comparison, 6+ samples per cell.

## What changed, in one paragraph

A FakeTLS hello is now parsed once and verified against **prepared candidates** (the HMAC key pads are hashed once per
reload, not per hello); a **hint cache** tries the secrets a client address matched before; and a **two-level CPU budget**
(per address, and process-wide) bounds what unmatched hellos can cost, fronting the over-budget ones to the cover site.
No byte the proxy sends for an accepted hello changed (golden tests untouched).

## Result 1 — cost per candidate (the scan itself), fake package

An unmatched hello is verified against every hosted secret. Per candidate, on the box:

| hello | before (`ReadClientHelloMulti`) | after (`Verify`, pad path) | change | allocs per candidate |
|---|---|---|---|---|
| 517 B (a real client) | 4.178 µs ± 6% | **2.499 µs ± 4%** | **−40.2%** (p=0.002, n=6) | 6 → **0** |
| 4,096 B | 16.29 µs ± 4% | 14.85 µs ± 4% | −8.8% (p=0.002, n=6) | 6 → 0 |

At the realistic hello size an unmatched scan costs 4.1 ms → 2.5 ms per 1,000 secrets and about 21 ms → 12.5 ms per 5,000.
(Only the `sec/candidate` rows pair like with like; the old per-op figure is a whole scan and the new one is one verify.)

**Pads decision (spec rule: keep only if ≥ 10% fewer ns per candidate at 517 B): KEPT.** −40%, far above the 17% the
block count alone predicts (the pads also remove `hmac.New`'s setup and five allocations per candidate). At a 4 KiB hello
the gain is 9%, as expected when message blocks dominate.

## Result 2 — a whole ee connection through the door, same-session A/B

The box drifts between sessions: the **dd door, whose code did not change**, read 3.07 ms (N=1,000) and 9.27 ms (N=5,000)
in the baseline session and 1.61 ms and 5.50 ms in the after session. A baseline-file-vs-after-file comparison therefore
cannot be used for timing. The figures below come from **alternating the baseline binary and the new binary on the box,
three rounds, n=12 each**:

| door, target sorted last | before | after | change | dd control (same session) |
|---|---|---|---|---|
| ee, 1,000 secrets | 5.605 ms ± 2% | **4.107 ms ± 5%** | **−26.7%** (p<0.001) | 1.617 → 1.606 ms, no change (p=0.76) |
| ee, 5,000 secrets | 22.95 ms ± 2% | **15.62 ms ± 7%** | **−31.95%** (p<0.001) | 5.611 → 5.441 ms, no change (p=0.38) |

Allocations per connection (deterministic): 1,000 secrets 6,281 → 277 (**−95.6%**), 5,000 secrets 30,290 → 279
(**−99.1%**); bytes 2.73 MiB → 85 KiB (−96.9%). The door is not CPU-free below the scan: parsing, the dial to the fake
Telegram and the load generator share the two cores, so the door-level gain (−32%) is smaller than the scan-level one (−40%).

## Result 3 — a returning client (the hint cache)

The same connection from an address that matched before, target sorted last among N secrets (new rows, `.../last/hinted`;
the benchmark asserts every iteration was a hint hit and the scan never ran):

| secrets | unhinted (before) | hinted (after) | |
|---|---|---|---|
| 1 | — | 937 µs | |
| 1,000 | 5.605 ms | **921–942 µs** | 6.0× faster |
| 5,000 | 22.95 ms | **930 µs** | **24.7× faster** (−96%) |

**Acceptance: "a hint hit at N = 5,000 within 1.3× of N = 1": 930 µs / 937 µs = 0.99×. Met.** A hinted handshake costs the
same at 5,000 secrets as at one, because it verifies one candidate. Allocations: 279 per connection at every N.

## Result 4 — what the budget costs

`BenchmarkScanBudgetReserve` (reserve + settle for one unhinted scan, on the box): **keyed ≈ 440 ns, unkeyed ≈ 305 ns, one
96-byte allocation.** Against a 1,000-candidate scan (2.5 ms) that is 0.018%; against a whole door handshake (~0.9 ms)
about 0.05%. The budget's calibration on the box read **296.6 ns/block** (five probe runs read 266 to 559): the plain
verify costs 336 ns/block and the pad path 207, so the configured ceilings are about 12% loose against the plain path and
about 30% strict against the pad path actually used — conservative, as designed.

## Acceptance checklist (spec §6)

| criterion | result |
|---|---|
| hint hit at N=5,000 within 1.3× of N=1 | **met: 0.99×** (930 µs vs 937 µs) |
| pads kept only if ≥ 10% faster per candidate | **kept: −40.2%** at 517 B |
| flood tests: zero verifications once the budget is spent; many-/64s flood bounded by the process-wide ceiling | **met by tests** (`TestManyAddressesAreStoppedByTheProcessWideBucket`, `TestForgedAddressesDoNotEscapeTheCeiling`, e2e refusal tests; each sabotage-checked) |
| existing tests pass untouched except the feature lists | **met**: golden-byte, snapshot, panel-contract and fronting files byte-identical to `origin/main` (`git diff --stat 3a5e2a9 HEAD` over them is empty); one existing row changed, the 129-block row of `TestAnOversizedHelloNeverConsultsHints`, as the spec says |
| full gate: pinned `golangci-lint` 2.13.2 (`config verify` then `run`), `go test -count=2 -race ./...` | **green locally**: 0 issues; every package ok; `go vet ./...`, `go build ./...` clean; `govulncheck`: no vulnerabilities affecting the code |

**No CI is claimed.** GitHub Actions is disabled for the account, so none of this ran in CI.

## Honest limits

- **2 vCPU, loopback.** The box measures per-core cost; 4–8 core scaling and the NIC are not measured. The door-level gain
  includes load-generator and kernel time on the same two cores.
- **The dd door is not in this piece** and stays O(N) (5.5 ms at 5,000 secrets); it has its own limiter.
- **First-time clients are unhelped by hints**: an address's first hello still scans (now 40% cheaper per candidate), and
  with `hints` off (the default unless `track-client-ips` is on) every client hello is a scan. The budget is what bounds that.
- **Hint hit rate on real traffic is not measured here**; `observe` mode and the `faketls_handshake` counters
  (`hinted` vs `scanned`) exist to read it in production.
- **The budget's door-level cost under attack is shown by tests, not by this report's benchmarks**: the door benchmarks run
  with the budget off on purpose (back-to-back unhinted hellos at N=5,000 exceed an enforcing budget by design).
- **Baseline-session noise**: see Result 2. The baseline file's dd rows are session drift, not a regression or a win.

## Sabotage and review

Every new test was sabotage-checked (about 110 deliberate breakages across the tasks, each failing a named test); the
benchmarks themselves verify what they measure (target position, hinted counter, byte counts). Each task had an
independent review; three of the seven needed a fix round (the door's candidate-to-secret mapping was not pinned; the
budget's calibration read 1.3–2.6× low and its clock was read outside the lock; two operator-facing doc claims were untrue
of the code), and all were fixed before any of the "after" numbers above were taken. The design itself was revised twice
before any code, after an advisor round and an independent adversarial review (which found that fixed nominal cost
units, instant refusal and refunds before the replay check each allowed a cheap lock-out).
