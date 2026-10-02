# ee at full speed, stealthy, with ad tags — design

Date: 2026-10-02. Status: approved in conversation, section by section.
Companion to `2026-10-02-performance-measurement-design.md`, whose Tier A
benchmarks for ee, dd, plain and the middle-proxy leg are pulled forward into
this project; its WEB and Tier B parts follow after.

## The goal, as stated

ee (FakeTLS) should have the best throughput and performance, while staying
stealthy, and must work with ad tags — throughput "really well and high".

Read as: a censor should not be able to tell ee traffic from the cover site's
HTTPS, passively or by probing; and an ee client on an ad-tagged secret goes
through Telegram's middle proxies (so the sponsored channel shows) at full
speed. The ad-tag ee path is the main production path.

## Where things stand

A throwaway probe on a 2 vCPU Linux VM (loopback; load generator sharing the
cores; one run each; every byte verified), in Mbit/s:

| Door | Down, 1 conn | Down, 16 conns | Up, 1 conn | Up, 16 conns |
|---|---|---|---|---|
| ee, as shipped | 21 | 207 | 2,203 | 5,494 |
| ee, pacing off (test only) | 5,045 | 5,328 | 3,549 | 5,746 |
| dd | 3,839 | 6,831 | 3,961 | 6,110 |
| plain | 3,530 | 6,981 | 3,682 | 6,176 |

On ee, pacing is the whole story for downloads. The doppelganger's write loop
(`mtglib/internal/doppel/conn.go`) waits a Weibull-distributed delay (k 0.378,
λ 1.73 ms, mean 6.8 ms) before every record of at most 16 KiB, which caps one
connection near 20 Mbit/s. Upstream mtg's loop and delay model are identical.
In upstream's blocking reports, the causes people identified were the Telegram
client's own ClientHello fingerprint (fixed client-side), active probing
(answered by domain fronting), an SNI/IP mismatch, and IP reputation — none was
record timing. That is evidence, not proof, that per-record delays cost far
more than they buy.

The ad-tag leg was not in the probe. Its download reads 16 bytes per system
call with one allocation per AES block (`middleproxy/frame.go`, `cbcConn.Read`);
its upload builds each RPC request through several allocations and makes one
system call per packet. ee uploads cost an allocation and two copies per TLS
record, at most one record per read (`mtglib/internal/tls/conn.go`).

## Decisions

- **Shaping: burst-aware (approach A).** Chosen over shrinking the per-record
  delay (still a ceiling, jitter on every record) and over dropping timing
  shaping entirely (gives up the mimicry where it is cheapest to keep).
- **Rollout: a canary.** Only real users on the censored network can show the
  new timing is still stealthy, so the new shape ships behind a setting,
  defaulting to today's behaviour; it runs on the live server for several
  days; the default flips in a later release only if nothing drops. Changes
  that alter nothing a censor can see — the middle-proxy leg, the ee read path,
  the bounded buffer — go straight to default.

## 1. ee write path: burst-aware shaping

| | `shaping = "record"` (today, default) | `shaping = "burst"` |
|---|---|---|
| Record sizes | 16 KiB max; optional DRS ramp; cover-calibrated noise | identical |
| Wait | one `Delay()` draw before every record | one draw when the connection wakes from idle |
| Within a burst | one record per wait | records back to back, up to 64 KiB of records per system call; TCP paces them |
| Buffer | capped at 256 KiB (new in both modes) | same |

- **Idle** means nothing written for `TLSRecordSizeResetAfter` (1 s) — the same
  threshold DRS already uses to reset record sizing, so "burst" means the same
  thing everywhere. Data arriving within 1 s of the last write is sent without
  a wait. Without this hold, each gap between Telegram's answers would start a
  new burst and bring the ceiling back. A media download is one burst at full
  speed; a chat message after a quiet second gets one website-like wait,
  typically under a millisecond.
- **Records are sized exactly as before**: each record's payload comes from
  `Stats.Size()`, so the DRS ramp and its idle reset are unchanged. Coalescing
  changes how many records share a system call, never their boundaries.
- **The bounded buffer** applies in both modes. `Write` blocks while 256 KiB is
  queued, until the writer drains it, the conn is stopped, or its context ends;
  the relay therefore stops reading from Telegram, and memory per connection is
  fixed. The speed cap still meters bytes in `countingConn` before they reach
  the doppelganger, so with the bound nothing is charged long before it is sent.
- **Ending a stream** is unchanged in meaning: `CloseWrite` delivers everything
  buffered before the FIN, bounded by `DrainTimeout`; under `"burst"` it drains
  at burst speed.
- **Setting**: `shaping` under `[defense.doppelganger]`, `"record"` or
  `"burst"`, default `"record"`. A new optional key: the panel's config contract
  is unaffected, and an older binary reports it as an unknown key.

## 2. The ad-tag (middle-proxy) leg at full speed

The wire format does not change; this is Telegram's own protocol between the
proxy and its middle proxies, so it ships on by default.

**Download (Telegram → client):**
- A 64 KiB buffered reader on the middle-proxy socket. `cbcConn.Read` decrypts
  as many whole blocks as fit the caller's buffer in one pass, in place; a read
  shorter than a block decrypts one block into a fixed per-connection array.
  No allocation per block.
- `readPacket` reuses one growing per-connection body buffer. The message it
  returns is valid until the next read, which every caller already respects.
- `middleConn.Read` serves the 4-byte intermediate length and the payload
  straight from that buffer — one copy, no allocation — and, when further
  packets are already buffered, takes them in the same read, so the client
  receives fewer, larger writes.

**Upload (client → Telegram):**
- Each frame — length, sequence number, RPC header, ad tag, payload, CRC32 and
  padding — is built in one reusable per-connection buffer and encrypted in
  place, replacing the `bytes.Buffer`s, the reflection-based `binary.Write`,
  `bytes.Repeat` and the encryption copy.
- All complete packets in one relay chunk go out in a single system call.

**Proof:** the existing golden trace test, which pins the exact bytes on the
wire, passes unchanged; new tests drive odd sizes — one-byte reads, packets
straddling the 64 KiB buffer, several packets per chunk, quick-acks — and
require a byte-identical stream to today's.

## 3. ee read path (upload)

The wire does not change; on by default.

- The record reader keeps its position within the current record and copies
  payload straight into the caller's buffer: no `LimitedReader` per record, no
  intermediate `bytes.Buffer`.
- One `Read` takes as many whole application-data records as fit, not one.
- The buffered reader grows from 4 KiB to 64 KiB.
- Acceptance is unchanged: the same version check, and records that are not
  application data are still discarded.

## Ad tags on ee, proven

A new end-to-end test: an ee client through the real FakeTLS door, with an
ad-tagged secret, against a fake middle proxy speaking the real RPC nonce,
handshake and AES-CBC. Every request must carry the ad tag, and bytes must
round-trip exactly both ways. The existing real-handshake fake middle proxy
moves from a `_test.go` file into a small test-support package so the `mtglib`
tests can use it. This test is written before the middle-proxy rewrite, so the
rewrite is checked against it.

## Build order

Each step is test-first and measured against the baseline before the next.

1. Tier A benchmarks for ee, dd, plain and the middle-proxy leg; a baseline
   from the bench box, committed.
2. The ee + ad-tag end-to-end test.
3. The middle-proxy leg (section 2).
4. The ee read path (section 3).
5. Burst shaping behind `shaping` (section 1), default `"record"`.
6. The full gate on Windows (`-race`) and Linux, and a before/after report.
7. Release and canary, each with the user's go-ahead at the time: deploy with
   `shaping = "burst"`, compare `/stats` — per-user connections, bytes,
   handshakes, frontings — over 3–7 days against the week before, then flip the
   default in a later release.

## Done when

- ee with `"burst"` downloads on one connection within about 20% of dd on the
  bench box.
- The middle-proxy leg makes over 10× fewer system calls per MB, close to zero
  allocations per packet, and moves more bytes; exact targets are set from the
  step-1 baseline.
- The ee read path makes zero allocations per record, at no lower throughput.
- The only change on the wire is burst timing: the golden tests pass untouched.
- Every byte is delivered in every test and benchmark.

## Risks

- **Stealth.** Burst timing is the one change a censor could see. Mitigated by
  the canary and the default staying `"record"` until it passes.
- **Backpressure.** A bounded buffer means a slow client now slows the relay's
  reads from Telegram. That is the intended behaviour, and the reason memory
  stops growing; the speed-limit and stream-end tests cover the edges.
- **2 vCPU and loopback.** The bench box measures per-core cost, not 4–8 core
  scaling or the NIC.

## Not in this project

WEB relay speed, the Tier B load test, changes to the speed limiter itself,
and the API — later projects.
