# WEB relay speed: report

The second project of the performance program: the WEB relay's lean data
path. It follows `docs/superpowers/specs/2026-10-03-web-relay-speed-design.md`
and the measurement report before it.

| | Tier A | Tier B |
|---|---|---|
| Before | `2026-10-03-web-speed-before.txt`, at 740eecc | `2026-10-03-web-speed-before-tierB.md`, at 740eecc |
| After | `2026-10-03-web-speed-after.txt`, at 6eb8acb | `2026-10-03-web-speed-after-tierB.md`, at 1edf750 |

Tier B's after binary is the relay as shipped. 6eb8acb changes only a test
harness, so it carries the same relay.

Box and protocol, unchanged from the earlier baselines:
- 2 vCPU, loopback, another project's database alongside.
- **Tier A:** six one-second samples at `GOMAXPROCS` 2 and 1, compared with
  benchstat.
- **Tier B:** the binary pinned to one core and mtgbench on the other, three
  runs per cell. dd is the reference row.

## What changed

- **Upload:**
  - one allocation per client message, down from six;
  - the mask removed eight bytes at a time;
  - DATA payloads sliced from the message, not copied, unless smaller than a
    quarter of it.
- **Download:**
  - backend reads land in pooled buffers sized to the stream: 4 KiB when
    idle, 64 KiB when busy;
  - DATA frames carry the pooled buffers to the client as they are;
  - each batch goes out in one vectored write, even behind a PROXY-protocol
    listener;
  - the outbox's memory budget charges a queued frame for the whole buffer
    it holds.
- **Sessions:**
  - tombstones grow on demand instead of 88 KB up front;
  - the bridge page shares its script instead of copying it;
  - a deleted session now ends.
- **Defects fixed on the way:**
  - The WebSocket reader unmasked continuation frames from the wrong
    offset, corrupting fragmented messages whose earlier fragments were not
    a multiple of four bytes.
  - A deleted session kept serving while its client held the socket.
  - A failed carrier write left the session's read side running.

## The spec's targets

From Tier B, against dd's row in the same run:

| measure | before | after | target | |
|---|---|---|---|---|
| WEB CPU per GB, 1 conn download | 2.96× dd | **1.46×** | ≤ 1.5× | met |
| WEB CPU per GB, 64 conns download | 2.06× dd | 1.63× | ≤ 1.5× | missed, close |
| WEB CPU per GB, 1 conn upload | 3.54× dd | 2.16× | ≤ 1.5× | missed |
| WEB CPU per GB, 64 conns upload | 3.12× dd | 2.15× | ≤ 1.5× | missed |
| RSS per idle WEB connection | 168 KiB | 83.9 KiB | ≤ 80 KiB | missed by 4 KiB |
| WEB connections per second | 657 | 707 (A/B: 648 → 772) | ≥ 1.5× | missed |

The CPU and memory targets came close; the setup target did not. The work
attacked per-message and per-session allocation, and a connection's setup
cost is dominated by something else: three HTTP round trips, a backend dial
and a PROXY header. That has not been profiled yet.

## Throughput

**Tier B**, the binary on one core (MB/s, and CPU-s per GB):

| | before | after | change |
|---|---|---|---|
| web, 1 conn, download | 148 (6.15) | 276 (3.06) | +86%, −50% CPU per GB |
| web, 1 conn, upload | 127 (7.51) | 213 (4.53) | +68%, −40% |
| web, 64 conns, download | 289 (3.42) | 380 (2.62) | +31%, −23% |
| web, 64 conns, upload | 187 (5.31) | 280 (3.55) | +50%, −33% |
| dd, 64 conns, download (reference) | 593 (1.66) | 600 (1.61) | unchanged |

**Tier A** (MiB/s, in-process with the test client), every row significant,
p = 0.002:

| | `GOMAXPROCS` 2 | `GOMAXPROCS` 1 |
|---|---|---|
| download, 1 / 16 / 64 conns | +52% / +50% / +46% | +42% / +43% / +35% |
| upload, 1 / 16 / 64 conns | +26% / +44% / +54% | +42% / +52% / +53% |
| geomean | +45% | +44% |

## Memory and allocation

| | before | after |
|---|---|---|
| Tier B RSS per idle WEB connection, relay and proxy | 168 KiB | 83.9 KiB |
| Tier A heap per idle WEB connection, with the test client | 213 KiB | 59 KiB |
| Tier A bytes allocated per op, downloads | — | −72% to −74% |
| Tier A bytes allocated per op, uploads | — | −49% |
| Tier A allocations per op, uploads | — | −29% to −32% |
| Tier A bytes allocated per handshake | 355 KiB | 179 KiB |

**Not zero.** Allocation counts rose for the single-connection download,
from 182 to 263 per op. These are small objects: `sync.Pool` boxes each
slice header it is handed, and the write vectors escape to the heap. That is
about 48 bytes per message, against the kilobytes removed (deferred,
below).

## Latency

- **Tier A:** the 100-byte round trip fell 14% at p50 (135 → 116 µs). p99
  and p99.9 did not move significantly.
- **Tier B:** no change. Before and after binaries, run back to back in one
  sitting on the box, gave WEB p50 259–269 µs and 260–270 µs.
- **A false alarm.** The main after run first showed WEB latency drifting
  from 279 to 644 µs over its three runs. That drift reproduced neither in
  the A/B nor locally, over 4,000 churned sessions with the proxy behind
  the relay. It was the box, not the code.

## Where the CPU goes now

Tier A profiles, 16 connections, 3 s, `GOMAXPROCS` 2 (flat %):

| | upload, before | upload, after | download, before | download, after |
|---|---|---|---|---|
| system calls | 34.5 | 53.4 | 41.9 | 56.2 |
| AES-CTR (the proxy's obfuscation) | 8.1 | 15.0 | 12.8 | 18.3 |
| relay's WebSocket unmask | **22.4** | 4.0 | — | — |
| buffer zeroing (`memclr`) | 8.3 | 6.8 | 11.1 | 4.2 |
| copies (`memmove`) | 7.0 | 4.2 | 17.8 | 7.4 |

System calls and the proxy's cipher now dominate. The relay's own share has
largely gone.

**The reference-counted pool stays unbuilt.** It was conditional on
zeroing still showing on the upload path. It does, at 6.8%, part of which is
the test client's own allocation, so a pool would win at most that. It
ranks below the system calls.

## What the review changed before these figures

A fresh review of the whole branch, before the box run, found four problems.
All are fixed and each has a test that fails without its fix.

- **Vectored writes behind a PROXY-protocol listener (the default).** The
  relay's socket is a wrapper there, and Go wrote each vector separately:
  up to 17 writes a batch. The WebSocket now writes to the TCP socket under
  the wrapper. Tier B runs `client-ip = "x-forwarded-for"`, so this path is
  unit-tested, not box-measured.
- **The memory budget.** It charged a DATA frame the bytes it carried while
  its pooled buffer held 64 KiB.
- **Message pinning.** A small payload could pin a whole client message.
- **A test.** It touched pooled buffers after releasing them, corrupting
  parallel tests under `-race`.

After the review, the first Tier A after run showed the tests' buffer
poisoning in the benchmarks: 12% of download CPU. Benchmarks now run without
it (6eb8acb), and the Tier A after figures above are that clean run.

## Limits

- 2 vCPU and loopback. Per-core cost is measured; the network card is not.
- Tier B measures the `x-forwarded-for` client-IP mode, as before.
- Tier A WEB figures include the test client's own WebSocket work.
- The box is shared. One after run drifted on its own; the A/B settled it.

## Next, by what is left

1. **Connection setup.** WEB opens about 700 connections a second against
   dd's 3,100. Profile the handshake, the bridge page, the session POST and
   the upgrade, before changing anything.
2. **Upload CPU,** still 2.2× dd. After the cipher, the remainder is system
   calls: one backend write per DATA frame.
3. **Small allocations:** the pool's boxed slice headers and the escaping
   vector list, about 48 bytes per message.
4. **Idle memory,** 84 KiB: the per-session goroutines and their stacks.
   Fewer goroutines per stream was out of this project's scope.
