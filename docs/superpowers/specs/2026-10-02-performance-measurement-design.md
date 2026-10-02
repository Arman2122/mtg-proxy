# Performance measurement — design

Date: 2026-10-02. Status: approved in conversation, section by section.
This is project 1 of the performance program; it builds the measurement and
records a baseline. It changes no production behaviour.

## Why

The goal is the fastest, leanest proxy on every door — ee (FakeTLS), dd,
plain (classic MTProto) and WEB — with the lowest added latency and good speed
capping and accounting. None of that can be claimed or improved safely without
numbers: the only benchmarks in the repo came with the mtg-multi import and
measure relay buffer strategies in isolation. Nothing measures a whole stream
through a door.

The program, in order: (1) measurement — this document; (2) data-path speed
per door, driven by what (1) finds; (3) speed capping and accounting;
(4) API, additive only (the Penhoon panel depends on today's API); (5)
architecture, improved inside 2–4 rather than as a rewrite.

## Decisions already made

- **Target hardware: a mid server** — 4–8 vCPU, 1–10 Gbit/s, thousands of
  users. Multi-core efficiency, lock contention and memory per connection are
  what matter, not one connection's peak alone.
- **ee pacing is decided after measuring.** The doppelganger waits a
  Weibull-distributed delay (k 0.378, λ 1.73 ms, mean 6.8 ms) before each
  16 KiB record, which caps one ee download at about 20 Mbit/s. That is a
  stealth feature. The benchmark reports ee both as shipped and unpaced; the
  choice is the user's, with the numbers in front of them.
- **Two tiers, A then B.** Tier A is in-process `testing.B` benchmarks — the
  yardstick every optimization is judged by. Tier B is a load test of the real
  binary for absolute numbers.
- **Correctness first.** Two defects found while mapping the data path were
  fixed before any measuring, so the baseline is taken on a relay that
  delivers every byte: the inverted half-close in `relay.Relay` (cd9b7c9) and
  the paced ee tail dropped at stream end (dc6d539).

## What is measured

Every scenario runs on each door. The Telegram side is direct; the ad-tag
(middle-proxy) leg is measured in Tier A at the package level (see Limits).

| Scenario | Answers | Reported |
|---|---|---|
| Bulk download and upload, 1 connection | the per-connection ceiling | MB/s |
| Bulk, 64 connections | total throughput and CPU efficiency | MB/s; CPU-seconds per GB (Tier B) |
| 64 connections of one user vs 64 users × 1 | whether per-user counters and buckets contend | MB/s difference |
| No speed cap vs a cap far above the rate | the limiter's cost when it is not limiting | Δ MB/s, Δ allocs |
| Ping-pong, 100-byte messages | added latency | p50 / p99 / p99.9 µs, against a no-proxy baseline |
| Handshake | connection setup cost | connect-to-first-byte; connections per second (Tier B) |
| 1,000 idle connections (Tier B also 5,000) | memory held by an open connection | bytes and goroutines per connection |
| ee paced (as shipped) vs unpaced | data for the stealth decision | MB/s per connection and total |
| ee, client reading slower than Telegram sends | the doppelganger buffer has no bound of its own | peak buffered bytes per connection |
| Speed cap accuracy (Tier B) | does a user capped at N get N, fairly | achieved rate over time; fairness across the user's connections |
| Accounting accuracy (Tier B) | do the proxy's counters match reality | proxy-reported bytes vs ground truth |

Every benchmark asserts byte-exact delivery and fails if a byte is missing. A
fast proxy that loses the end of a download is not a result.

Allocation counts (B/op, allocs/op) come with every Tier A number, and CPU and
allocation profiles are taken for the scenarios that look expensive, so
project 2 starts from where the time goes, not only how much.

## Tier A — in-process benchmarks

Test files only; nothing here is linked into the release binary.

- `mtglib/door_bench_test.go` — ee, dd and plain through the real `ServeConn`,
  on the existing entry harness: real loopback TCP, and a fake Telegram that
  pushes and sinks raw bytes. The endpoints never decrypt, so almost all the
  CPU measured is the proxy's own. ee runs twice: with the production pacing
  model, and with `Ganger.Unpace()`.
- `internal/webrelay/chain_bench_test.go` — WEB through the real relay and the real
  proxy, on the existing relay–proxy chain harness.
- `mtglib/internal/middleproxy/stream_bench_test.go` — the ad-tag leg over real TCP
  against the existing fake middle proxy, which speaks the real RPC nonce,
  handshake and AES-CBC through the package's own key schedule. It is extended
  to stream answers back, so download can be measured as well as upload.

Benchmarks are named `BenchmarkDoor/<door>/<scenario>`, use `b.SetBytes` for
MB/s, and report latency percentiles and per-connection memory through
`b.ReportMetric`.

**Run protocol.** Cross-compiled with `go test -c`, run on the bench box (below)
at `GOMAXPROCS=2` and `GOMAXPROCS=1`, ten runs each, compared with `benchstat`.
A full Tier A run is kept to about ten minutes. Results are committed as
`benchmarks/results/<date>-<commit>-tierA.txt`: that file is the baseline an
optimization has to beat with statistical significance, not one lucky run.

## Tier B — the real binary under load

`tools/mtgbench/`, a separate program in this module. The release build
compiles only the root package, so it never ships.

- It runs the real `mtg-proxy` and, for WEB, the real `mtg-proxy web-relay` as
  separate processes, with a config it generates.
- **Fake Telegram through SOCKS5.** The binary cannot be pointed at a fake data
  centre, but with exactly one `[network] proxies` entry every outbound dial
  goes through that SOCKS5 proxy — Telegram, the startup config fetch, the
  cover site — and the SOCKS connection gets the same socket options a direct
  Telegram connection would. mtgbench's SOCKS5 server answers "connected" for
  Telegram's data-centre addresses and then *is* the data centre on that same
  socket: it reads the 64-byte handshake, then pushes, sinks or echoes for the
  scenario. Every other destination is refused, so the proxy falls back to its
  built-in data-centre list. No extra copy hop, no production change.
- **Client side, shared with the tests.** The code that speaks each door — the
  forged FakeTLS hello, obfuscated2 frames, TLS record framing, the WEB session
  protocol — lives only in `_test.go` files today. It moves into a new internal
  package, `internal/testclient`, that both the tests and mtgbench import, so the tests lose their
  copies rather than a second copy appearing.
- **Measurement.** The proxy is pinned to one core with `taskset`, mtgbench to
  the other: the result is per-core capacity. CPU time and RSS come from the
  proxy's `/proc/<pid>` files; latency is a histogram in mtgbench; the proxy's
  own API supplies its per-user counters for the accounting check.
- **Run protocol.** Each scenario runs for 20 seconds after a 5-second
  warm-up, three times; the median is reported with the spread. A full Tier B
  run is kept to about fifteen minutes.
- **Output.** JSON and a Markdown table, committed as
  `benchmarks/results/<date>-<commit>-tierB.md`.

## The bench box

A Linux VM designated by the user: 2 vCPU, 4 GB RAM, 10 Gbit/s. It also runs
another project's database and monitoring and is shared with other people, so:

- everything lives in one directory, `/root/mtg-bench`, removed at the end;
- nothing is installed: binaries are cross-compiled here and copied over;
- loopback ports only, in a range checked free first (47000 and up), never a
  port another service holds;
- disk is nearly full, so no large files or packet captures are left behind;
- a load run occupies both cores and slows the other services while it lasts,
  so runs are short and bounded.

## Limits, stated with every result

- **2 vCPU, not 4–8.** Per-core numbers and 1→2 core scaling are measured;
  scaling beyond two cores is not.
- **Loopback, not the NIC.** These tests measure the proxy's own cost — CPU per
  byte, added latency, memory. The network path itself would need a client on
  a second machine; that is added only if the numbers point there.
- **The ad-tag path is Tier A only.** The binary fetches its middle-proxy list
  over HTTPS from `core.telegram.org`, which cannot be faked without a real
  certificate.
- **Tier B handshake times include one SOCKS5 round trip** on loopback.

## Known candidates, to be measured rather than assumed

Mapped from the code before any measuring; project 2 decides by the numbers.

- Middle proxy: `cbcConn.Read` decrypts one 16-byte block per call with a fresh
  allocation, and nothing buffers the socket, so a 16 KiB packet is about a
  thousand read syscalls and allocations (`middleproxy/frame.go`). Verified in
  the code.
- Per-user counters (`bytesIn`, `bytesOut`, quota) share a cache line and are
  written by every chunk of every connection of that user.
- `time.Now` and a socket deadline reset on every read and write
  (`conns.go`, `counting_conn.go`).
- With metrics on, a blocking capacity-1 channel send per chunk
  (`event_stream.go`).
- WEB relay: extra copies per frame, a process-wide budget lock with broadcast
  wake-ups, two socket writes per WebSocket message.
- `TCP_NOTSENT_LOWAT` of 128 KiB on Telegram sockets, and its effect on upload.
- The doppelganger buffer, which has no bound of its own.

## Done when

- Tier A and Tier B run on the bench box from documented commands, end to end,
  and every benchmark's byte-exact check passes.
- A baseline is committed for each tier at a named commit.
- A short report sets out, per door: per-connection and per-core throughput,
  added latency, memory per connection, the cost of the limiter, the
  accounting and speed-cap accuracy, the ee paced/unpaced comparison, and the
  top costs from the profiles — with the limits above stated alongside.
- The ee pacing decision is put to the user with those numbers.

## Out of scope here

Optimizing anything (project 2), changing the speed limiter or accounting
(project 3), API changes (project 4), and any change to production behaviour.
