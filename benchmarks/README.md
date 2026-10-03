# Benchmarks

Two kinds live in this repository:

- **Door benchmarks** (`mtglib/door_bench_test.go`, and
  `mtglib/internal/middleproxy/stream_bench_test.go` for the ad-tag leg): whole
  streams through `ServeConn` on real loopback sockets, per door. These are the
  yardstick a performance change is judged by.
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

## Limits

Two vCPU, not the 4–8 of the target server: per-core cost and one-to-two core
scaling are measured, scaling beyond that is not. Loopback, not a network
card: these measure the proxy's own cost — CPU per byte, added latency, memory
per connection.
