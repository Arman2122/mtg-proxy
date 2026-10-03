# Measurement report: every door, the real binary under load

The performance program's first project ends here. It took two tiers of
measurements, both at commit a34c2cc on the 2 vCPU bench box:

- **Tier A:** in-process benchmarks of every door, including WEB.
- **Tier B:** the real `mtg-proxy` binary, pinned to one core, under load from
  `tools/mtgbench` on the other core.

Raw figures:

- `2026-10-03-tierA-web-and-additions.txt`: the new Tier A rows.
- `2026-10-03-tierB.md` and `.json`: Tier B, every cell, every run.
- `2026-10-02-tierA-after.txt`: the earlier Tier A rows for ee, dd and plain.

How to read the numbers:

- **Tier B cells** are the median of three runs. Each run is a 2 s warm-up
  then 5 s measured. Ranges are in the raw files.
- **MB/s** in Tier B is 10^6 bytes; benchstat's MiB/s in Tier A is 2^20.
- **Per core:** in Tier B the binary has one core. For WEB the relay runs on
  that same core.

## Throughput

**Tier B, the binary on one core** (MB/s):

| door | 1 conn ↓ | 1 conn ↑ | 64 conns ↓ | 64 conns ↑ | CPU-s per GB, 64 ↓ / ↑ |
|---|---|---|---|---|---|
| dd | 451 | 451 | 605 | 593 | 1.62 / 1.65 |
| plain | 450 | 457 | 597 | 610 | 1.64 / 1.62 |
| ee-burst | 422 | 399 | 506 | 545 | 1.90 / 1.77 |
| ee-record (shipped) | **2.39** | 151 | 148 | 578 | 3.96 / 1.68 |
| web | 164 | 137 | 269 | 185 | 3.61 / 5.37 |

**Whose core ran out.** The binary's core was 0.91–0.99 busy in every
uncapped row except ee-record downloads, which are paced, not CPU-bound. These
figures are the binary's per-core capacity. mtgbench's own core reached
0.93–0.95 on dd and plain at 64 connections, so those two are close to a tie
with the load generator. Treat them as a floor.

**Tier A at 64 connections, `GOMAXPROCS=2`** (MiB/s, in-process):

| | dd | plain | ee-burst | ee-unpaced | ee-record | web |
|---|---|---|---|---|---|---|
| download | 763 | 760 | 715 | 653 | 63 | 339 |
| upload | 715 | 697 | 637 | 623 | 595 | 245 |

The WEB row in Tier A includes the test client's own WebSocket work,
in-process.

## Added latency

A 100-byte round trip. **Tier B** (µs):

| door | p50 | p99 | p99.9 | p50 added over direct |
|---|---|---|---|---|
| direct, no proxy | 23.6 | 51.0 | 103 | — |
| plain | 124 | 453 | 1,924 | +100 |
| dd | 128 | 390 | 1,221 | +104 |
| ee-burst | 142 | 492 | 2,067 | +118 |
| web | 260 | 911 | 2,229 | +236 |
| ee-record | 1,359 | 88,284 | 400,749 | +1,335 |

**Tier A** (in-process, p50 µs): direct 20.4, dd 45.7, ee-burst 79, web 132,
ee-record 1,382.

- Tier B's larger gap has a cause: every hop there is a wake-up in a
  different process, on two pinned cores.
- ee-record's p99.9 rests on about 800 samples per run, so it is the
  thinnest figure here.

## Connection setup

**Tier B**, 8 connections at a time, each one whole: dial, one-byte echo,
close.

| door | connections/s | first byte p50 ms | p99 ms |
|---|---|---|---|
| plain | 3,169 | 2.18 | 7.38 |
| dd | 3,071 | 2.24 | 8.43 |
| ee-record | 874 | 3.28 | 109 |
| ee-burst | 783 | 4.54 | 96.5 |
| web | 579 | 10.8 | 32.0 |

- The times include the proxy's SOCKS5 round trip to the data centre.
- No hello was fronted. A fresh anti-replay filter rarely false-positives.
- ee's p99 near 100 ms on both shapings, against dd's 8 ms, is the
  doppelganger pacing the server flight.

## Memory per connection

**Tier B RSS** (every process of the binary; KiB per idle connection, each
first proven with an echo, on a fresh process):

| door | 1,000 | 5,000 |
|---|---|---|
| plain | 33.9 | — |
| dd | 34.1 | 32.6 |
| ee-burst | 64.3 | — |
| ee-record | 72.5 | 72.0 |
| web | 168 | — |

**Tier A**, heap and goroutines per idle connection:

| door | heap | goroutines |
|---|---|---|
| dd | 42 KB | 2 |
| ee-record | 78 KB | 3 |
| web | 220–230 KB | 7 |

The Tier A WEB figure carries the test client's own side, under 16 KiB.
mtgbench's own heap was 3–9 KiB per connection.

**Slow readers.** 64 ee clients reading 100 KiB/s while the data centre
sends as fast as it can, for 20 s (KiB of RSS per connection):

| | at 5 s | at 20 s | growth |
|---|---|---|---|
| ee-record | 1,258 | 1,262 | 4 |
| ee-burst | 996 | 1,170 | **174** |

Both are about 2.4× the doppelganger's ~512 KiB queue bound. ee-burst was
still growing when the run ended.

## Speed limits and accounting

**The limiter's cost.** dd, 64 downloads:

| | MB/s | CPU-s per GB |
|---|---|---|
| no cap | 599 | 1.62 |
| a cap far above the rate | 578 | 1.65 |

That is −3.5% (ranges overlap) and +2% CPU. One user's 64 connections
against 64 users of one each: 591 against 583 MB/s. Per-user counters do not
contend measurably.

**Cap accuracy.** One user with 8 connections, at 1 and 10 MiB/s, on speed,
speed-up and speed-down, on ee, dd and WEB:

- **Accuracy:** achieved over target was 1.00 in every cell (0.99–1.04 across
  runs).
- **Fairness:** Jain's index across the connections was 0.99–1.00.
- **Single seconds:** at 10 MiB/s every second stayed within 0.96–1.03.
  1 MiB/s uploads swung 0.75–1.19 from second to second; their mean is
  exact. That is the coarse grain of 64 KiB commands at 128 KiB/s per
  connection, not the limiter.

**Accounting.** On every door, one connection uploads 8 MiB and downloads
16 MiB.

- The proxy's per-user `bytes_in` and `bytes_out` matched the client to the
  byte, on every door.
- For WEB, so did the relay's `bytes.up` and `bytes.down`, once the client's
  64-byte obfuscated2 frame is subtracted.

A client that resets mid-download leaves bytes counted but never delivered.
Median gap, with the range:

| door | gap |
|---|---|
| ee-record | 287 KiB |
| plain | 532 KiB |
| dd | 879 KiB (5 KiB – 1.3 MiB) |
| ee-burst | 1,035 KiB |
| web | 5,133 KiB (4.4 – 8.6 MiB) |

The WEB gap is the relay's 4 MiB window plus the sockets. The proxy's
counters never fell below what the client received, nor rose above what the
data centre sent.

## Where the CPU goes

CPU profiles of the three cells that cost the most per byte, taken from their
Tier A equivalents (`GOMAXPROCS=2`, 16 connections, 3 s). These are the heads
of `go tool pprof -top`, flat %.

**WEB upload** (252 MB/s; the WEB rows also count the test client):

| % | function |
|---|---|
| 34.5 | syscalls |
| 22.4 | `internal/webrelay/ws.unmask` — the relay unmasks client frames |
| 8.3 | `memclrNoHeapPointers` — fresh buffers, zeroed |
| 8.1 | AES-CTR, the proxy's obfuscation |
| 7.0 | `memmove` |
| 3.4 | the test client's own `maskBytes` |

**WEB download** (320 MB/s):

| % | function |
|---|---|
| 41.9 | syscalls |
| 17.8 | `memmove` |
| 12.8 | AES-CTR |
| 11.1 | `memclrNoHeapPointers` |

The relay's `stream.pump` is 11.5% cumulative.

**ee-record download** (22 MB/s at 16 connections): only 25% of one core was
busy. The cost is the pacing, not the CPU. Of what it did use:

| % | function |
|---|---|
| 48.5 | syscalls — many small paced writes |
| 15.5 | AES-CTR |
| 7.2 | `memmove` |
| 6.2 | `futex` |

## Limits, stated with every figure

- **2 vCPU and loopback.** Per-core cost and 1→2 core scaling are measured.
  Scaling to the target's 4–8 cores is not, and neither is the network card.
- **The SOCKS5 hop on the Telegram leg.** Tier B's handshake times include
  one SOCKS5 round trip on loopback.
- **`TCP_NOTSENT_LOWAT` is unmeasured.** The SOCKS socket does not get the
  Telegram socket options.
- **The ad-tag (middle-proxy) leg is measured in Tier A only.**
- **ee unpaced is Tier A only.** It has no config switch.
- **The box is shared.** Another project's database ran throughout, and load
  swung 0.2–1.8, so ±10% on a single cell is noise.

## What projects 2–5 should take on first

Ranked by measured cost.

1. **The WEB relay (project 2, WEB speed).** It is the most expensive door on
   every axis:
   - 2.2–3.3× dd's CPU per byte;
   - 5× dd's memory per idle connection (168 against 34 KiB);
   - 3.5× the goroutines;
   - a fifth of dd's connection rate;
   - more than twice its added latency.

   The profiles name the first targets:
   - the relay's byte-at-a-time WebSocket unmask, 22% of upload CPU (the
     test client's word-at-a-time version costs a seventh as much);
   - a fresh buffer per message (`memclr`, 8–11%);
   - copies (`memmove`, 18% of download).

   Also: the zombie-carrier defect found in this project. It is pinned as a
   skipped test (`TestADeletedSessionStopsServing`).
2. **The ee pacing decision (for the owner).** As shipped, `record` pacing
   costs ee:
   - 2.4 MB/s for a single download, against 422 with `burst`;
   - 148 MB/s per core at 64 connections, against 506;
   - +1.3 ms of added latency at p50 and 0.4 s at p99.9.

   `burst` keeps ee at 84% of dd's per-core throughput. The canary on penhoon
   has run `burst` since 2026-10-03.
3. **The slow-reader buffer (architecture).** A client that reads slowly holds
   about 1.2 MiB of the proxy's memory, 2.4× the documented bound. Under
   `burst` it was still growing at 20 s. Ten thousand slow readers would be
   about 12 GB.
4. **Syscalls (project 2, every door).** 34–48% of CPU in every profile is in
   the kernel. Batching reads and writes is the general lever. dd's ceiling
   is about 600 MB/s per core at 1.62 CPU-s per GB.
5. **Speed limits and accounting (project 3) can wait.**
   - Caps are accurate and fair, and the limiter costs about 3%.
   - Per-user counters do not contend, and clean accounting is exact.
   - The one imprecision: a reset client is charged for bytes it never
     received, up to ~1.3 MiB on the TCP doors and ~8.6 MiB on WEB. That
     matters only for quota precision.
6. **The API (project 4).** Nothing measured here bears on it.
