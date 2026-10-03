# Measurement, completed: WEB and the real binary under load — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish project 1 of the performance program: a Tier A benchmark for
the WEB door, the Tier A scenarios the ee project skipped, and Tier B, the
real `mtg-proxy` binary under load. The Tier B numbers include speed-cap
accuracy, accounting accuracy and memory per connection. Baselines and a
report are committed, so projects 2–5 (WEB speed, speed limiting and
accounting, API, architecture) start from numbers.

**Architecture:** The client side of every door moves out of `_test.go` files
into `internal/testclient`. It returns errors, never takes `testing.TB`, and
imports nothing that imports `mtglib`, so tests and the load tool share one
copy. The WEB client gains real flow control and works past the relay's
4 MiB window. Tier A for WEB reuses the in-process relay–proxy chain.
`tools/mtgbench` runs the real binaries. Its SOCKS5 server answers for
Telegram's data centres and then *is* the data centre on the same socket.

**Tech Stack:** Go 1.26.8, testify, `golang.org/x/perf/cmd/benchstat`,
golangci-lint 2.13.2, Linux `/proc` and `taskset` on the bench box.

**Spec:** `docs/superpowers/specs/2026-10-02-performance-measurement-design.md`.
Its Tier A ee/dd/plain/middle-proxy parts shipped with the ee project
(`benchmarks/results/2026-10-02-tierA-*.txt`). This plan is the rest.

## Spec corrections (ruled while mapping the code)

The spec was written before the code was mapped in this detail. Each point
below is a correction of fact, and the spec is amended to match in Task 1's
commit.

1. **`internal/testclient` cannot import `mtglib` or `mtglib/internal/...`.**
   - Go's `internal` rule keeps `mtglib/internal/tls` and `.../tls/fake` out
     of reach.
   - `mtglib`'s and `internal/webrelay`'s in-package tests would form import
     cycles.
   - So testclient imports only `mtglib/obfuscation`, `essentials`,
     `internal/webrelay/frame` and the standard library.
   - It copies four TLS constants and a 15-line record reader, takes keys as
     `[16]byte`, and takes the WEB capability as a string.
2. **The test WEB client stalls after 4 MiB.**
   - It never returns credit (`frame.NewWindow`), and never honours the
     relay's.
   - It writes only 7- and 16-bit WebSocket lengths.
   - It does not answer pings, so an idle carrier dies after about 50 s.
   - A bulk WEB benchmark needs all four fixed. This is client code only.
3. **Only Telegram-bound dials go through `[network] proxies`.** That covers
   data centres, the middle proxy and HTTP fetches.
   - Domain fronting, the doppelganger scout and the public-IP lookup use
     `NativeDialer` and dial directly.
   - The SOCKS socket gets none of the Telegram socket options, so
     `TCP_NOTSENT_LOWAT` cannot be measured in Tier B.
   - mtgbench's config therefore disables scouting, sets `public-ipv4`, and
     points `[domain-fronting]` at a local listener of its own.
4. **ee unpaced has no config switch.** `Ganger.Unpace` is a test seam. Tier B
   runs ee as `record` (the default) and `burst`; unpaced stays Tier A only.

## Global Constraints

- **No production change.** New code lives in `_test.go` files,
  `internal/testclient` and `tools/mtgbench`, plus docs and
  `benchmarks/results`.
- **Neither new package reaches the release binary.** The release builds only
  the root package. Task 5 asserts that
  `go list -deps . | grep -E 'testclient|mtgbench'` is empty.
- Go 1.26.8; golangci-lint **2.13.2**. Every commit passes
  `golangci-lint config verify && golangci-lint run` (0 issues) and
  `golangci-lint fmt --diff` (empty).
- Every task ends green on `go test -race` over its packages. Task 8 runs
  `MTG_REQUIRE_BROWSER_HARNESS=1 go test -count=2 -race ./...`.
- **Every benchmark and scenario checks every byte.** A short count fails the
  run; a fast number that lost data is not a result.
- **Golden files are untouched.** The FakeTLS and middle-proxy goldens must
  pass unchanged after the helpers move. That is the proof the moved client
  code is the same client.
- **Bench box:**
  - Work in `/root/mtg-bench` only and remove it at the end.
  - Install nothing; cross-compile with `CGO_ENABLED=0` and `chmod +x`
    after `scp`.
  - Loopback ports 47000–47099 only, checked free before every run.
  - `ulimit -n 65536` for Tier B (5,000 idle connections are four sockets
    each on the WEB door).
  - Keep each Tier A run to about 10 minutes and each Tier B run to about
    15, and wait for TIME_WAIT under 200 between runs.
- Repo style: LF line endings, linear history, no attribution lines, commit
  messages saying what was wrong, what changed and how it was verified.

## Review Focus

1. **WEB flow control under sustained transfer.** 16 MiB each way through one
   stream, four times the initial window, must arrive byte-exact, with no
   `ErrCreditExhausted` and no stall. Pinned in Task 2
   (`TestAWebStreamOutlastsTheInitialWindow`).
2. **mtgbench never leaves a process behind** on the shared box: not on a
   failed scenario, not on SIGINT, not on a panic. Pinned in Task 5
   (`TestRunnerKillsChildrenOnEveryExit`).
3. **Anti-replay false positives in the handshake-rate scenario.** About
   0.1% of hellos are taken for replays and fronted. They are counted and
   reported as fronted, not as errors. Pinned in Task 6
   (`TestHandshakeScenarioCountsFrontingSeparately`).
4. **Accounting after an abrupt disconnect.** Only clean transfers must match
   exactly. A client that vanishes mid-download leaves bytes in kernel
   buffers, so the proxy may have counted more than the client received.
   This is reported as a bound (counted ≥ received, and the gap is at most
   the socket buffers), not as an error. Pinned in Task 7
   (`TestAccountingBoundsAnAbruptDisconnect`).
5. **The first second of a capped stream.** The speed limiter starts with one
   second of burst, so rate accuracy is computed only after the first second.
   Pinned in Task 7 (`TestCapAccuracyIgnoresTheBurstSecond`).

---

### Task 1: `internal/testclient` — the client side of ee, dd and plain

**Files:**
- Create: `internal/testclient/doc.go`, `faketls.go`, `records.go`,
  `obfs.go`, `sockets.go`, and `faketls_test.go`, `records_test.go`
- Create: `mtglib/testclient_helpers_test.go`, holding thin `testing.TB`
  wrappers so the existing call sites keep their names
- Modify: `mtglib/proxy_fronting_test.go`, `proxy_entry_test.go`,
  `proxy_golden_faketls_test.go`, `door_bench_test.go` to delete their copies
- Modify: the spec, applying the corrections above

**Interfaces — Produces:**
```go
package testclient
const RecordHeaderSize = 5; const MaxRecordPayload = 16379   // copied, with the source named
type Record struct { Type byte; Version [2]byte; Payload, Raw []byte }
func ReadRecord(r io.Reader) (Record, error)
func ApplicationRecord(payload []byte) []byte
func ClientHello(key [16]byte, sni string, sessionID []byte) ([]byte, error)
func ReadServerFlight(r io.Reader) ([]Record, []byte, error) // exactly 3 records; flight bytes for the HMAC
func NewRecordConn(c essentials.Conn) essentials.Conn          // client-side record layer: writes ≤16379-byte records, reads payloads
func ObfuscatedFrame(key [16]byte, tag obfuscation.ConnectionTag, dc int) ([]byte, error)
func ResetOnClose(c net.Conn) error                            // SetLinger(0) on a *net.TCPConn
```

- [ ] **Step 1: Write the failing tests.**
  - `TestClientHelloCarriesTheDigest`: recompute HMAC-SHA256(key, hello with
    the random zeroed). It must equal the random XOR the timestamp in the
    last 4 bytes, per the formula `fake.ReadClientHello` checks.
  - `TestRecordConnRoundTrip`: 100 KiB written through `NewRecordConn` over
    `net.Pipe` reads back byte-exact, every record ≤ 16379 bytes of payload.
  - `TestReadServerFlightNeedsThreeRecords`.
- [ ] **Step 2: Run them.**
  Run: `go test ./internal/testclient/`
  Expected: FAIL, because the package does not exist.
- [ ] **Step 3: Implement the package** by moving the bodies from the test
  files named above. Keep the ClientHello bytes identical: same fields, same
  order.
- [ ] **Step 4: Switch mtglib.** Point `fakeTLSClientHello`,
  `tlsApplicationRecord`, `goldenReadRecord`/`goldenReadFlight`,
  `skipServerFlight`, `obfuscatedFrame` and `resetOnClose` at testclient as
  thin wrappers in `testclient_helpers_test.go` that `require.NoError`.
  Delete the old bodies.
- [ ] **Step 5: Run the suites.**
  Run: `go test -race ./internal/testclient/ ./mtglib/...`
  Expected: PASS, with the golden tests unchanged:
  `git diff --stat -- '*testdata*'` is empty.
- [ ] **Step 6: Commit.** Message:
  `test: one client for ee, dd and plain, shared by tests and tools`
  (including the spec amendment).

### Task 2: the WEB client, with real flow control

**Files:**
- Create: `internal/testclient/web.go`, `websocket.go`, and
  `internal/testclient/web_test.go` (package `testclient_test`)
- Modify: `internal/webrelay/integration_test.go`,
  `relay_proxy_chain_test.go`, `metrics_wiring_test.go` to delete `wsClient`,
  `dialCarrier`, `bootstrapFromBridge`, `spendBootstrap` and `streamConn` in
  favour of testclient. `ws/ws_test.go` keeps its raw client: it tests
  protocol abuse.

**Interfaces — Produces:**
```go
type WebOptions struct { Origin string; ForwardedFor string; DialTimeout time.Duration }
func OpenWebSession(ctx context.Context, baseURL, capability string, o WebOptions) (*WebSession, error) // bridge GET → bootstrap → POST session → WS upgrade
func (s *WebSession) OpenStream(id uint32) (*WebStream, error)
func (s *WebSession) Delete(ctx context.Context) error                                                 // DELETE /api/v1/session
type WebStream struct{ /* essentials.Conn */ }
```
`WebStream` behaviour:
- Returns a `WINDOW` frame for every 1 MiB consumed.
- Blocks writes while the relay's uplink credit is spent.
- Writes WebSocket payloads with 7-, 16- and 64-bit lengths, in frames of at
  most 64 KiB, mirroring `MaxRelayDataChunk`.
- Answers pings with pongs.
- `Close` sends `CLOSE`.

- [ ] **Step 1: Write the failing test.**
  `TestAWebStreamOutlastsTheInitialWindow` lives in
  `internal/webrelay/relay_proxy_chain_test.go`. 16 MiB down and 16 MiB up
  through one stream must arrive byte-exact within 20 s. Run it against
  today's `streamConn`.
  Expected: FAIL — the download stalls at 4 MiB, or the upload is cut with
  `ErrCreditExhausted`.
- [ ] **Step 2: Implement the WEB client.**
  - The capability is passed in already derived; the caller uses
    `webrelay.Derive`.
  - Copy the unexported protocol paths, with their source named:
    `/api/v1/session`, `/api/v1/ws`, `?bridge=`, `tproxy-v1.`.
- [ ] **Step 3: Switch the webrelay tests** to testclient and delete the
  copies.
- [ ] **Step 4: Run the suites.**
  Run: `go test -race ./internal/testclient/ ./internal/webrelay/...`
  Expected: PASS, including the new test,
  `TestTheRelayProxyChainDoesNotLeakUnderChurn` and
  `TestAWebClientIsHeldToTheUsersSpeedLimit`.
- [ ] **Step 5: Commit.** Message:
  `test: a WEB client that keeps a stream going past the first 4 MiB`.

### Task 3: Tier A for the WEB door

**Files:**
- Create: `internal/webrelay/chain_bench_test.go`
- Modify: `relay_proxy_chain_test.go`. `newChainWithLimits` takes
  `testing.TB`, and a `telegramMode` (`echo` | `push` | `sink`). `push` and
  `sink` read the 64-byte handshake and then only write or only read, like
  the door benchmarks' fake Telegram, so the CPU measured is the relay's and
  the proxy's.

**Benchmarks**, named so `benchstat` lines them up with
`mtglib`'s `BenchmarkDoor`:
- `BenchmarkDoor/web/{download,upload}/conns={1,16,64}`: `b.SetBytes`, with
  byte-exact delivery checked.
- `BenchmarkDoorRoundTrip/web`: 100-byte ping-pong, reporting p50-µs, p99-µs
  and p999-µs.
- `BenchmarkDoorHandshake/web`: bridge, session, upgrade, open stream and
  first byte, together.
- `BenchmarkDoorIdle/web`: 1,000 sessions of one stream each, reporting
  heap-B/stream and goroutines/stream.

- [ ] **Step 1: Write the benchmarks and run them once each.**
  Run: `go test -run '^$' -bench 'BenchmarkDoor' -benchtime 1x ./internal/webrelay/`
  Expected: every sub-benchmark completes, with no byte-count failure.
- [ ] **Step 2: Add a short-count guard.**
  `TestDoorWebBenchmarkFailsOnAShortCount` swaps in a fake Telegram that
  drops the last byte, and requires the bulk helper to return an error.
- [ ] **Step 3: Run the suite.**
  Run: `go test -race ./internal/webrelay/...`
  Expected: PASS.
- [ ] **Step 4: Commit.** Message:
  `bench: the WEB door end to end, beside the others`.

### Task 4: the Tier A scenarios the ee project skipped

**Files:**
- Modify: `mtglib/door_bench_test.go`

**What it adds:**
- `conns=64` beside 1 and 16 in `BenchmarkDoor`.
- A **direct** baseline row, `BenchmarkDoorRoundTrip/direct`: client to fake
  Telegram with no proxy. Each door's added latency is then that door's
  figure minus this one.
- The round trip at **100 bytes**, as the spec names it. The 1 KiB variant
  stays as `size=1KiB`, so the committed baseline still compares.

- [ ] **Step 1: Run the new rows.**
  Run: `go test -run '^$' -bench 'BenchmarkDoor(RoundTrip)?/' -benchtime 1x ./mtglib/`
  Expected: the new rows appear and pass.
- [ ] **Step 2: Run the suite.**
  Run: `go test -race ./mtglib/`
  Expected: PASS.
- [ ] **Step 3: Commit.** Message:
  `bench: 64 connections, and latency against no proxy at all`.

### Task 5: `tools/mtgbench`, the harness

**Files:**
- Create in `tools/mtgbench/`:
  - `main.go` for the flags
  - `config.go` for the TOML generator
  - `socks.go` for SOCKS5 plus the fake data centre
  - `cover.go`, a local fronting target that accepts and counts
  - `proc.go` for the processes, `taskset`, and `/proc` CPU and RSS
  - `clients.go` for door dialers built on testclient
  - `report.go` for JSON and Markdown
  - tests beside each

**Interfaces — Produces:**
```go
type Door string // "ee-record", "ee-burst", "dd", "plain", "web"
type User struct { Name string; Key [16]byte }
type Caps struct { Speed, Up, Down string } // config spellings, e.g. "10MB"; empty means none
type Setup struct { Dir string; Users []User; Doors []Door; Shaping string; Caps map[string]Caps; BasePort int }
func WriteConfig(s Setup) (path string, err error)         // passes config.Parse + Validate + ValidateWeb
type DCMode int // DCPush, DCSink, DCEcho, DCPingPong
func StartSOCKS(addr string, mode func() DCMode) (*SOCKS, error)
type Runner struct{ /* proxy and relay processes */ }
func StartRunner(ctx context.Context, bin string, cfg string, pinCore int) (*Runner, error) // Close kills every child, on every path
func (r *Runner) CPUSeconds() (float64, error); func (r *Runner) RSSBytes() (int64, error)
func Dial(ctx context.Context, door Door, u User) (essentials.Conn, error) // a door-specific client, handshake done
```

**The generated config:**
- ee on `bind-to`.
- A plain loopback `[[listener]]` for `dd` and `plain`.
- A PROXY-protocol `[[listener]]` as the WEB backend, plus `[web]`. The relay
  takes `client-ip = "x-forwarded-for"` so the load tool needs no PROXY
  writer.
- `[network] proxies` set to mtgbench's SOCKS5.
- `scout-covers = false`, and `public-ipv4 = "127.0.0.1"`.
- `[domain-fronting]` set to `cover.go`'s listener.
- `concurrency = 16384`.
- Anti-replay stays on, as shipped.

**The SOCKS5 server:**
- No authentication, CONNECT only.
- CONNECT to one of `essentials.TelegramCoreAddresses` is answered with
  success. It then runs `obfuscation.Obfuscator{}.ReadHandshake` and serves
  the scenario's mode.
- Any other destination is refused (reply 0x02).

- [ ] **Step 1: Write the failing tests.**
  - `TestGeneratedConfigValidates`, which also runs `ValidateWeb`.
  - `TestSOCKSServesOnlyTelegram`, driven by the `golang.org/x/net/proxy`
    client.
  - `TestRunnerKillsChildrenOnEveryExit`: a fake child process. After
    `Close`, a context cancel, and a panic recovered in the test, no process
    from the run is alive.
  - `TestReleaseBinaryDoesNotLinkTheTools`: `go list -deps .` contains
    neither package.
- [ ] **Step 2: Implement the harness.** `-smoke` runs every door once, 1 MiB
  each way, byte-exact.
- [ ] **Step 3: Smoke-run it locally.**
  Run: `go build -o mtg-proxy . && go run ./tools/mtgbench -bin ./mtg-proxy -smoke`
  Expected: `smoke: ee-record ok, ee-burst ok, dd ok, plain ok, web ok`.
  On Windows, CPU and RSS report "n/a".
- [ ] **Step 4: Commit.** Message:
  `tools: mtgbench, the real binary under load through a fake data centre`.

### Task 6: Tier B scenarios — throughput, latency, setup, memory

**Files:**
- Create: `tools/mtgbench/scenarios.go` and `scenarios_test.go`

**Scenarios.** Each scenario's results come from three runs; each run is a
2 s warm-up then a 10 s measurement. The spec's 20 s per run is shortened so
the full matrix fits about 15 minutes on the box (ruled; the spread is
reported).
- **`bulk`:** 1 and 64 connections, download and upload, on every door.
  Reports MB/s and the proxy's CPU-seconds per GB.
- **`handshake`:** connections per second, and connect-to-first-byte p50 and
  p99. Fronted connections are counted separately.
- **`latency`:** 100-byte ping-pong, p50, p99 and p99.9, against a direct
  SOCKS-free baseline.
- **`idle`:** RSS per connection for 1,000 connections on every door and
  5,000 on ee and dd. WEB uses one session per connection.
- **`contention`:** 64 connections of one user against 64 users of one each.
- **`limiter`:** the same bulk run with no cap, and with a cap far above the
  rate. This is the limiter's cost when it never waits.
- **`slow-reader`:** 64 ee connections whose clients read 100 KiB/s while the
  data centre pushes. RSS per connection must stay near the doppelganger's
  bound (about 512 KiB of buffer) and not grow with time.

- [ ] **Step 1: Write the failing tests.**
  - `TestHandshakeScenarioCountsFrontingSeparately`: an injected replay
    verdict is reported as fronted, not as an error.
  - `TestBulkScenarioFailsOnAShortCount`.
- [ ] **Step 2: Implement the scenarios.** The Markdown output has one table
  per scenario, rows for doors, and the median with its spread.
- [ ] **Step 3: Run the tests.**
  Run: `go test -race ./tools/mtgbench/`
  Expected: PASS.
- [ ] **Step 4: Commit.** Message:
  `tools(mtgbench): throughput, latency, setup and memory per door`.

### Task 7: Tier B accuracy — speed caps and accounting

**Files:**
- Create: `tools/mtgbench/accuracy.go` and `accuracy_test.go`

**Speed cap.** Caps of 1 MiB/s and 10 MiB/s on `speed`, and separately on
`speed-up` and `speed-down`, run on ee, dd and WEB.
- One user holds 8 connections.
- Delivered bytes are sampled per second, and the burst second is dropped.
- Reported: achieved over target (mean, p10, p90), and Jain's fairness index
  across that user's connections.

**Accounting.** Each user sends exactly K bytes up and receives exactly L
bytes down, on every door.
- Compared afterwards: `/stats` `bytes_in` and `bytes_out`, and for WEB also
  the relay's `/stats` `bytes.up` and `bytes.down`.
- Clean transfers must match exactly.
- An abrupt disconnect is reported as a bound (Review Focus 4).

- [ ] **Step 1: Write the failing tests.**
  - `TestCapAccuracyIgnoresTheBurstSecond`
  - `TestJainIndex`, against known vectors
  - `TestAccountingBoundsAnAbruptDisconnect`
- [ ] **Step 2: Implement the scenarios.**
- [ ] **Step 3: Run them locally.**
  Run: `go test -race ./tools/mtgbench/` and
  `go run ./tools/mtgbench -bin ./mtg-proxy -scenario accounting -doors dd -runs 1`
  Expected: PASS, and the accounting table shows a difference of 0 on dd.
- [ ] **Step 4: Commit.** Message:
  `tools(mtgbench): does a capped user get the cap, and does the proxy count every byte`.

### Task 8: run it, commit the baselines, write the report

**Files:**
- Create:
  - `benchmarks/results/2026-10-03-tierA-web-and-additions.txt`
  - `benchmarks/results/2026-10-03-tierB.md` and `.json`
  - `benchmarks/results/2026-10-03-measurement-report.md`
- Modify: `benchmarks/README.md`, with how to run the WEB benchmarks and
  mtgbench on the box

- [ ] **Step 1: Run the full gate.**
  - `MTG_REQUIRE_BROWSER_HARNESS=1 go test -count=2 -race ./...`
  - lint: `config verify` and `run`
  - `golangci-lint fmt --diff`
  - `govulncheck ./...`
- [ ] **Step 2: Run Tier A on the box.**
  - New rows only: `webrelay.test` and the `mtglib` additions.
  - `GOMAXPROCS` 2 and 1, 6 × 1 s, as the committed baselines were.
  - CPU profiles of the three most expensive scenarios, with
    `-test.cpuprofile`. The profiles stay off the repository; their
    `go tool pprof -top` heads go into the report.
- [ ] **Step 3: Run Tier B on the box.**
  - Command: `taskset -c 1 ./mtgbench -bin ./mtg-proxy -pin 0 -out tierB`.
  - Keep it to about 15 minutes, then remove `/root/mtg-bench`.
- [ ] **Step 4: Write the report** by door:
  - per-connection and per-core throughput, CPU per GB
  - added latency against direct
  - memory per connection, at 1,000 and 5,000
  - the limiter's cost
  - cap accuracy and fairness, and accounting accuracy
  - the top profile costs
  - the limits:
    - 2 vCPU and loopback
    - the SOCKS hop on the Telegram leg
    - LOWAT unmeasured
    - ad-tag in Tier A only
    - ee unpaced in Tier A only

  End it with **what projects 2–5 should take on first**, ranked by measured
  cost.
- [ ] **Step 5: Commit.** Message: `bench: measurement completed — WEB and the real binary under load`.
