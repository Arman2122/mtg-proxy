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
- **Stealth defaults (section 4): replay protection on, and the fake
  certificate sized from each cover site automatically.** Both reduce what a
  censor can learn, so they ship on by default.

## 1. ee write path: burst-aware shaping

| | `shaping = "record"` (today, default) | `shaping = "burst"` |
|---|---|---|
| Record sizes | 16 KiB max; optional DRS ramp; cover-calibrated noise | drawn the same way; more short records (see below) |
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
- **Record sizes are drawn exactly as before**: each record's payload comes
  from `Stats.Size()`, so the DRS ramp and its idle reset are unchanged, and a
  drawn size that does not fit one system call carries to the next. In both
  modes a record is cut short when less is queued than was drawn. Record
  shaping's wait lets the queue fill first; burst shaping sends what is
  queued, so it cuts more records short when Telegram's answer arrives in
  pieces. That difference is accepted, not engineered away: holding a record
  back until it fills would add latency to every small exchange, which is
  what burst shaping exists to remove. The canary watches for it.
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

**Proof:** golden files of the exact bytes on the wire, both directions,
captured from today's code before the rewrite (a comment in `frame.go` speaks
of a golden trace test, but none exists), and the rewrite must reproduce them
byte for byte; new tests drive odd sizes — one-byte reads, packets
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

## 4. Stealth defaults

Added after reviewing what an ee deployment exposes today. Both change a
default; both reduce what a censor can learn, so neither waits for the canary.

**Replay protection on by default.** `[defense.anti-replay] enabled` defaults
to `false` in the code (`internal/cli/run_proxy.go`); only the example config
sets it. The Penhoon panel never writes that section, so every panel-managed
proxy runs without it: a censor that records a real user's ClientHello and
replays it within the time-skew window (3 s by default) gets a proxy answer —
the classic way to confirm a proxy. With protection on, a replayed hello is
handed to the cover site like any other stranger.
- The default becomes `true`; `enabled = false` still turns it off.
- Cost, stated in the docs: 1 MiB per proxy process (the stable Bloom filter's
  default size), and at its default error rate about one genuine connection
  attempt in a thousand is taken for a replay and fronted; the client retries
  with a fresh hello.

**The fake certificate sized from the cover site, out of the box.** The
handshake's single application-data record stands in for the real server's
encrypted handshake (certificate chain and the rest). Today it is sized from a
cover site only when `[defense.doppelganger] urls` is configured, otherwise
from a generic 2,500–4,700 byte range; and even when configured there is one
size for the whole process, though secrets can name different cover sites.
- With `urls` empty, the scout measures each distinct cover host named by the
  ee secrets, at `https://<host>/`, dialling the same address domain fronting
  would use — so a deployment whose cover host resolves back to this server
  (an SNI router) does not scout itself.
- Sizes are kept per host; a handshake uses the size measured for the host in
  the client's SNI, and falls back to today's behaviour while a host is
  unmeasured.
- A host seen for the first time — at start, or when a secret change brings a
  new one — is measured promptly; after that, on the existing raid cadence
  (every 6 h, `repeats_per_raid` requests). With no configured URLs, the same
  raids also supply the delay statistics.
- Configured `urls` keep working as today and take precedence for timing.

**Open question, not in scope:** the fake ServerHello always answers with an
x25519 key share. Every Telegram ClientHello on file offers x25519 only, so
that matches; whether current app versions now offer a post-quantum group
(which a modern cover site would pick) is unverified, and needs a capture from
current apps before anything changes.

## Ad tags on ee, proven

A new end-to-end test: an ee client through the real FakeTLS door, with an
ad-tagged secret, against a fake middle proxy speaking the real RPC nonce,
handshake and AES-CBC. Every request must carry the ad tag, and bytes must
round-trip exactly both ways. The existing real-handshake fake middle proxy
moves from a `_test.go` file into an exported, documented test-support file of
the `middleproxy` package itself — it needs that package's own frame, CBC and
key-schedule code, so a separate package could only duplicate them — where the
`mtglib` tests can use it. This test is written before the middle-proxy rewrite, so the
rewrite is checked against it.

## Build order

Each step is test-first and measured against the baseline before the next.

1. Tier A benchmarks for ee, dd, plain and the middle-proxy leg; a baseline
   from the bench box, committed.
2. The ee + ad-tag end-to-end test.
3. The middle-proxy leg (section 2).
4. The ee read path (section 3).
5. Burst shaping behind `shaping` (section 1), default `"record"`.
6. Stealth defaults (section 4): replay protection on by default; per-host
   certificate-size calibration from the cover sites.
7. The full gate on Windows (`-race`) and Linux, and a before/after report.
8. Release and canary, each with the user's go-ahead at the time: deploy with
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
- Replay protection is on without configuration: a replayed hello is fronted
  in a test against a proxy built from a config with no `[defense]` section.
- A proxy with no doppelganger URLs sizes its fake certificate from the cover
  host the client named: tested with two secrets naming two hosts of different
  certificate sizes.

## Risks

- **Stealth.** Burst timing is the one change a censor could see. Mitigated by
  the canary and the default staying `"record"` until it passes.
- **Backpressure.** A bounded buffer means a slow client now slows the relay's
  reads from Telegram. That is the intended behaviour, and the reason memory
  stops growing; the speed-limit and stream-end tests cover the edges.
- **Replay false positives.** About one genuine connection attempt in a
  thousand is fronted and retried by the client; the error rate stays
  configurable.
- **Scouting is outbound traffic.** The server periodically fetches its cover
  sites' front pages, as monitoring would; the cadence is the existing one.
- **2 vCPU and loopback.** The bench box measures per-core cost, not 4–8 core
  scaling or the NIC.

## Not in this project

WEB relay speed, the Tier B load test, changes to the speed limiter itself,
and the API — later projects.
