# Benchmarks

Three kinds live in this repository:

- **Door benchmarks** (Tier A: `mtglib/door_bench_test.go`,
  `internal/webrelay/chain_bench_test.go` for the WEB door, and
  `mtglib/internal/middleproxy/stream_bench_test.go` for the ad-tag leg): whole
  streams through `ServeConn` on real loopback sockets, per door. These are the
  yardstick a performance change is judged by.
- **mtgbench** (Tier B: `tools/mtgbench`): the real `mtg-proxy` binary, and its
  WEB relay, as separate processes under load from real clients, with CPU and
  memory read from `/proc`. It also checks that a capped user gets the cap and
  that the proxy counts every byte. It is not part of the release binary.
- **Micro-benchmarks** in this directory and in `mtglib/internal/relay/`,
  inherited from mtg-multi; `ANALYSIS.md` discusses them.

Results are committed under `results/`, one file per run, so a change can be
compared with what came before it rather than with memory.

## What the door benchmarks report

| Benchmark | Reports |
|---|---|
| `BenchmarkDoor/<door>/<download\|upload>/conns=<1\|16\|64>` | MB/s; B/op and allocs/op |
| `BenchmarkDoor/dd/one-user-16-conns`, `dd/16-users` | the cost of one user's shared counters and bucket |
| `BenchmarkDoor/dd/cap-far-above` | the speed limiter's cost when it never waits |
| `BenchmarkDoorRoundTrip/<door>` | a 100-byte round trip: `p50-µs`, `p99-µs`, `p999-µs` |
| `BenchmarkDoorRoundTrip/direct` | the same with no proxy: a door's added latency is its figure minus this |
| `BenchmarkDoorHandshake/<door>` | one whole connection, set up and torn down |
| `BenchmarkDoorHandshake/<ee-unpaced\|dd>/secrets=<1\|100\|1000\|5000>/<first\|last>` | the same against a door hosting that many secrets, the client's sorting first or last in the list; the ee rows send a 517-byte hello |
| `BenchmarkDoorHandshake/ee-unpaced/secrets=<1\|1000\|5000>/last/hinted` | the same from one fixed public address that has connected before, so the door verifies the hello against its hint and does not scan; it fails unless every timed connection was a hint hit |
| `BenchmarkScanBudgetReserve/<keyed\|unkeyed>` | the scan budget's own cost: ns/op and allocs/op of one `reserve` and `settle` |
| `BenchmarkReadClientHelloMulti/plain/N=<1\|10\|100\|1000\|5000>/<first\|last\|miss>/hello=<517\|4096>` | the FakeTLS scan alone (`./mtglib/internal/tls/fake`): ns/op, `ns/candidate` and allocs/op |
| `BenchmarkDoorIdle/<door>` | `heap-B/conn`, `stack-B/conn`, `goroutines/conn` for 1,000 open streams |

Every bulk benchmark counts every byte and fails on a short count. The fake
Telegram never decrypts and the load generator keeps its buffers from setup,
so the CPU and allocations measured are the proxy's.

Doors: `ee-record` (FakeTLS with the doppelganger pacing as shipped),
`ee-burst` (the same with `shaping = "burst"`), `ee-unpaced` (the same with
`Ganger.Unpace`), `dd`, `plain`, and `web`: the WEB relay in front of the
proxy, in `internal/webrelay/chain_bench_test.go` (run it with
`./internal/webrelay/` beside `./mtglib/`). Its figures include the test
client's own WebSocket work.

Take latency numbers on Linux: Go's clock on Windows advances in steps of
about half a millisecond.

## Running them on the bench box

The bench box is a 2 vCPU Linux VM that also runs another project's database.
On it:

- work only in `/root/mtg-bench`, and remove it at the end of a session;
- install nothing — binaries are cross-compiled here and copied over;
- loopback only;
- keep one run to about ten minutes of load, which is why runs are six
  one-second samples rather than ten two-second ones;
- raise the descriptor limit first (`ulimit -n 16384`): the idle benchmark
  holds 1,000 streams, four sockets each.

The test's own sockets are reset rather than closed at the end of a stream,
because thousands of connections a second otherwise fill the kernel's
TIME_WAIT table (16,384 there) and stall a dial for ~15 s. If a handshake
benchmark ever reports a mean far above its neighbours, check
`ss -Htan state time-wait | wc -l` before suspecting the proxy.

```bash
# here
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o mtglib.test ./mtglib
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o middleproxy.test ./mtglib/internal/middleproxy
scp mtglib.test middleproxy.test <box>:/root/mtg-bench/

# on the box, once per GOMAXPROCS value (2, then 1)
cd /root/mtg-bench && chmod +x *.test && ulimit -n 16384
GOMAXPROCS=2 ./mtglib.test -test.run '^$' -test.bench . -test.benchmem -test.count 6 -test.benchtime 1s > mtglib-p2.txt
GOMAXPROCS=2 ./middleproxy.test -test.run '^$' -test.bench . -test.benchmem -test.count 6 -test.benchtime 1s > middleproxy-p2.txt

# back here: compare with the committed baseline
GOBIN=<scratch> go install golang.org/x/perf/cmd/benchstat@latest
benchstat results/2026-10-02-tierA-baseline.txt <new file>
```

`-test.run '^$'` matters: a test binary run away from its source tree cannot
find golden files, so the tests themselves would fail there.

The WEB door's Tier A benchmarks are a package of their own:

```bash
# here
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o webrelay.test ./internal/webrelay

# on the box
GOMAXPROCS=2 ./webrelay.test -test.run '^$' -test.bench BenchmarkDoor -test.benchmem -test.count 6 -test.benchtime 1s > webrelay-p2.txt
```

Its figures include the test client's own WebSocket work, in the same process.

The FakeTLS scan by itself (`BenchmarkReadClientHelloMulti`) is a package of its
own too. Its thirty rows at six one-second samples are about three minutes, and
the secrets-count rows of `BenchmarkDoorHandshake` add nineteen more rows to what
`-test.bench .` runs on `mtglib.test`, so filter rather than run everything in
one ten-minute session. A `-bench` element is an unanchored regular expression:
`N=100` also selects `N=1000`, so write `N=100$`. The three `last/hinted` rows
sit below the `last` rows, so a pattern ending in `last` selects them too.

```bash
# here
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o fake.test ./mtglib/internal/tls/fake

# on the box
GOMAXPROCS=2 ./fake.test -test.run '^$' -test.bench ReadClientHelloMulti -test.benchmem -test.count 6 -test.benchtime 1s > fake-p2.txt
GOMAXPROCS=2 ./mtglib.test -test.run '^$' -test.bench 'DoorHandshake/(ee-unpaced|dd)/secrets=' -test.benchmem -test.count 6 -test.benchtime 1s > door-secrets-p2.txt
GOMAXPROCS=2 ./mtglib.test -test.run '^$' -test.bench 'DoorHandshake/ee-unpaced/secrets=[0-9]+/last/hinted$' -test.benchmem -test.count 6 -test.benchtime 1s > door-hinted-p2.txt
GOMAXPROCS=2 ./mtglib.test -test.run '^$' -test.bench ScanBudgetReserve -test.benchmem -test.count 6 -test.benchtime 1s > budget-p2.txt
```

## mtgbench on the bench box

mtgbench starts the binary with a config of its own: Telegram is mtgbench's
SOCKS5 server, which answers for Telegram's data centres and then *is* the data
centre; domain fronting goes to a local listener of its own; nothing leaves the
machine. It uses loopback ports base to base+32 (`-base-port`, 47000 by
default), checks they are free before it starts anything, and stops every
process it started however the run ends (on Linux its children die with it
even if it is killed).

```bash
# here
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o mtg-proxy .
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o mtgbench ./tools/mtgbench
scp mtg-proxy mtgbench <box>:/root/mtg-bench/

# on the box: the binary on core 0, mtgbench on core 1, so figures are per core
cd /root/mtg-bench && chmod +x mtg-proxy mtgbench && ulimit -n 65536
taskset -c 1 ./mtgbench -bin ./mtg-proxy -pin 0 -dir /root/mtg-bench/work -out tierB \
    -scenarios bulk,handshake,latency,idle,contention,limiter,slow-reader
taskset -c 1 ./mtgbench -bin ./mtg-proxy -pin 0 -dir /root/mtg-bench/work -out tierB-2 \
    -scenarios caps,accounting
```

Every scenario runs three times, each a 2 s warm-up then 5 s measured, and
each table cell is the median with the range. The whole matrix took 25
minutes on the box, so it runs in the two parts above: about 18 minutes (3 of
them idle, while the WEB handshake cell's TIME_WAIT clears) and 7. Wait for
`ss -Htan state time-wait | wc -l` to drop under 200 between them. `-warmup`,
`-measure`, `-runs`, `-scenarios`, `-doors` and `-shaping` narrow a run;
`-smoke` moves 1 MiB each way through every door once and stops.

The report is Markdown on stdout; `-out` writes `tierB.md` and `tierB.json`.
A row that failed says why, the rest of the run goes on, and mtgbench exits
non-zero naming every failed row. Off Linux, CPU and memory read n/a.

## Limits

Two vCPU, not the 4–8 of the target server: per-core cost and one-to-two core
scaling are measured, scaling beyond that is not. Loopback, not a network
card: these measure the proxy's own cost — CPU per byte, added latency, memory
per connection.
