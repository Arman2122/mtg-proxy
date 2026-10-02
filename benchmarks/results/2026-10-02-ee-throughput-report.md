# ee throughput — before and after

Project: `docs/superpowers/specs/2026-10-02-ee-throughput-design.md`.
Before: `2026-10-02-tierA-baseline.txt` (main at d716492, with the benchmark
harness). After: `2026-10-02-tierA-after.txt` (the branch at 32b23dd). Both
come from the same bench box, with the same settings: 6 × 1 s samples, at
GOMAXPROCS=2 and at GOMAXPROCS=1, loopback only. Every comparison below is
`benchstat baseline after`. "~" means no significant difference (p ≥ 0.05).
Throughput is in MiB/s; multiply by 8.4 for Mbit/s.

## Throughput, per door

| Door | Direction | Conns | 2 cores before → after | 1 core before → after |
|---|---|---|---|---|
| ee, `record` (default) | download | 1 | 1.9 → 2.1 (~) | 2.3 → 2.3 (~) |
| | download | 16 | 16.9 → 17.6 (~) | 19.0 → 20.1 (~) |
| | upload | 1 | 276 → 356 (**+29%**) | 314 → 387 (**+23%**) |
| | upload | 16 | 517 → 609 (**+18%**) | 287 → 347 (~, +21%) |
| ee, `burst` (new) | download | 1 | — → **462** | — → **506** |
| | download | 16 | — → 723 | — → 409 |
| | upload | 1 | — → 375 | — → 389 |
| | upload | 16 | — → 608 | — → 347 |
| ee, pacing off (test only) | download | 1 | 472 → 500 (~) | 455 → 445 (~) |
| | upload | 1 | 278 → 367 (**+32%**) | 328 → 397 (**+21%**) |
| | upload | 16 | 522 → 623 (**+19%**) | 281 → 344 (**+22%**) |
| dd | download | 1 | 370 → 388 (~) | 485 → 476 (~) |
| | download | 16 | 738 → 756 (~) | 433 → 421 (−3%) |
| plain | download | 1 | 363 → 402 (+11%) | 486 → 478 (~) |
| ad-tag leg, 16 KiB answers | download | 1 | 8.2 → **343** (42×) | 7.1 → **202** (28×) |
| | upload | 1 | 8.6 → **349** (40×) | 7.4 → **194** (26×) |
| ad-tag leg, 256 B answers | download | 1 | 6.8 → 28 (4×) | 5.5 → 61 (11×) |
| | upload | 1 | 6.6 → 27 (4×) | 5.4 → 59 (11×) |

`record` downloads are unchanged on purpose: its per-record wait is the
shipped behaviour, kept as the default until `burst` has passed the canary.

This project changed no dd or plain code, yet their lines move by −4% to +11%
with p < 0.05. That is the noise floor of a shared box, with a database
running beside the benchmarks (load 0.7–1.6). A single line under about 10%
here is not evidence either way.

## Latency, one 1 KiB request and its answer

| Door | p50, 2 cores / 1 core | p99, 2 cores / 1 core |
|---|---|---|
| ee, `record` | 1,323 / 1,338 µs (~) | 103,600 / 84,490 µs (~) |
| ee, `burst` | **77 / 47 µs** | **260 / 167 µs** |
| ee, pacing off | 87 / 48 µs (~) | 262 / 176 µs (−8% / ~) |
| dd | 47 / 45 µs (~) | 159 / 160 µs |

`burst` takes the ee round trip from dd plus a millisecond and more, with a
100 ms tail, to dd plus the TLS layer: about 2 µs at one core. An ee round
trip allocates 3 times, down from 5.

## Memory

| | Before | After |
|---|---|---|
| Idle ee connection, `record` | 68 KiB | 77 KiB (+12%) |
| Idle ee connection, `burst` | — | 61 KiB |
| Idle dd / plain connection | 40 KiB | 40 KiB |
| ee handshake, bytes allocated | 72 KiB | 80 KiB (+12%) |
| ee connection under a slow client | grows without bound | 256 KiB plus one write, at most |
| ee queue after a download | kept for the connection's life | let go after 1 s idle |

The +9 KiB per ee connection is the record reader's buffer, which grew from
4 KiB to 16 KiB (the spec asked for 64 KiB; the ledger ruling has the
measurements). `burst` holds less than `record` when idle: its batch buffer
is pooled per write, while `record`'s writer keeps a 16 KiB buffer for the
connection's life.

## Done when, item by item

1. **ee with `burst` downloads on one connection within about 20% of dd.**
   Met, and it is ahead of dd: 462 vs 388 MiB/s on 2 cores (1.19×) and 506
   vs 476 on 1 core (1.06×). Sixteen connections: 723 vs 756 and 409 vs 421
   (0.96× and 0.97×). Burst sends up to 64 KiB of records per system call,
   and the relay makes one call per chunk.
2. **The middle-proxy leg: over 10× fewer system calls per MB, close to zero
   allocations per packet, more bytes moved.**
   - Download reads per MiB: 65,664 → 64–74 for 16 KiB answers (about 900×
     fewer), and 73,728 → 72 for 256 B answers on one core. On two cores,
     256 B answers take 2,663 reads per MiB, because the reader catches up
     with the writer and takes smaller reads.
   - Upload writes per MiB do not move (64 and 4,096). The benchmark sends
     one packet per relay chunk, so it was already one write per packet.
     What the rewrite changed, several packets per chunk in one write, is
     shown by `TestMiddleConnUploadWritesOnce` (eight packets, one write),
     not by this number.
   - Allocations per packet: 1,040 → 1 (download, 16 KiB), 1,034 → 0
     (upload, 16 KiB), 32–37 → 0–1 (256 B). Bytes allocated per packet:
     108–125 KB → 6–8 B (16 KiB), 2.1–2.4 KB → 4 B (256 B).
   - Throughput: see the table, 4× to 42×.
3. **The ee read path makes zero allocations per record, at no lower
   throughput.** `TestConnReadAllocatesNothing` (0 allocs per 16 KiB read).
   An ee upload now allocates exactly what a dd upload does (74 per
   benchmark op, down from 265), and moves 18–32% more bytes.
4. **The only change on the wire is burst timing; the golden tests pass
   untouched.** The middle-proxy goldens have not changed since they were
   captured before the rewrite (25e5aec). `TestMiddleConnUploadGolden`,
   `TestMiddleConnDownloadGolden` and the FakeTLS flight goldens pass.
   `TestRecordShapingIsUnchanged` and `TestBurstKeepsDRSRecordSizes` hold the
   record sizing. One qualification, now in the docs: burst draws record
   sizes the same way, but it sends more short records, because with no wait
   before each record less has queued.
5. **Every byte is delivered in every test and benchmark.** Every bulk
   benchmark counts its bytes and fails on a short count: 0 failures in both
   runs. Tests: `TestStreamEndDeliversTheWholeAnswer`,
   `TestConnWriteBlocksAtTheBufferBound` (8 MiB through the 256 KiB bound, in
   both shapings),
   `TestFakeTLSClientWithAdTagRoundTripsThroughTheMiddleProxy`.
6. **Replay protection is on without configuration.**
   `TestAntiReplayIsOnWithoutConfiguration`: a config with no `[defense]`
   section catches a replay. `TestFakeTLSReplayIsFronted`: an ee replay is
   handed to the cover site. `TestAntiReplayCanStillBeTurnedOff`: an explicit
   `enabled = false` still works.
7. **A proxy with no doppelganger URLs sizes its fake certificate from the
   cover host the client named.** `TestHandshakeIsSizedLikeTheNamedCoverSite`
   covers this end to end: two secrets name two cover sites with
   certificates of different sizes, and each client's handshake is sized
   like its own site. Reverting the proxy to the single global size fails
   it. `TestCoverHostsAreMeasuredSeparately` and
   `TestNewCoverHostIsMeasuredPromptly` cover the measuring itself.

## What the re-measure caught

A fix from the review of the bounded queue made the queue let go of its
buffer every time the writer emptied it (b7b1948). Inside a download that
happens many times a second, and each time the buffer was regrown from
nothing. On the box, ee downloads fell by half (`burst`, one connection:
490 → 239 MiB/s), and allocation rose from ~5 KiB to 2.2 MiB per op. 32b23dd
replaces the release with one that waits for a second with no writes, and
`TestConnQueueKeepsItsBufferThroughATransfer` now pins the cost. The numbers
above come from after that fix.

## Gate

- Windows, `MTG_REQUIRE_BROWSER_HARNESS=1 go test -count=2 -race ./...`:
  26/26 packages.
- Linux (the box): the tests of every changed package pass —
  `mtglib`, `middleproxy`, `tls`, `relay`, `config` and `cli` at b7b1948,
  `doppel` again at 32b23dd. `config`'s `TestTypeBlocklistURI` reads its own
  package's `config.go`, so it needs the source file beside the binary.
- `golangci-lint` 2.13.2: 0 issues. `golangci-lint fmt --diff`: empty.
  `govulncheck`: nothing reachable.

## Limits

- **Two vCPU and loopback.** These numbers measure the proxy's own cost: CPU
  per byte, added latency, memory per connection. They do not measure
  scaling past two cores or a network card.
- **A shared box.** Another project's database ran alongside. Six one-second
  samples keep each run near ten minutes of load, so the intervals are wide,
  ±10% on a single line.
- **`burst` is not yet proven stealthy.** It changes timing, and the share of
  short records, both of which a censor can see. It stays behind
  `shaping = "burst"` until the canary has run on the live server.
- **Not measured yet:** the WEB relay, and Tier B (real clients through a
  real network). Both belong to later projects.
- **`record` numbers are wide** (±20–40%), because its pacing is random by
  design.
