# WEB relay speed: design

Project 2 of the performance program, the first by measured cost. It follows
`benchmarks/results/2026-10-03-measurement-report.md`.

## Why

The measurement put WEB as the most expensive door on every axis. Against dd,
on one core of the bench box:

| | dd | web |
|---|---|---|
| CPU-s per GB (64 conns, ↓ / ↑) | 1.62 / 1.65 | 3.61 / 5.37 |
| RSS per idle connection | 34 KiB | 168 KiB |
| connections per second | 3,071 | 579 |
| added round-trip latency, p50 | +104 µs | +236 µs |

The CPU profiles and the code name the causes.

- **Upload.**
  - Every client message is allocated three times and copied twice: once
    per WebSocket frame, once more by an `append` onto nil, and once per
    frame by the frame decoder.
  - The mask is then removed one byte at a time, with a modulo per byte:
    `ws.unmask` is 22% of upload CPU.
- **Download.**
  - Every backend read is copied into a fresh payload. The batch encoder
    copies it into a new buffer, and `append(nil, …)` copies that once more.
  - The message then goes out in two system calls, header and payload. That
    is three allocations (zeroed: `memclr` is 8–11% of CPU), three copies
    (`memmove` is 18% of download CPU) and two writes per message.
- **Idle and setup.**
  - Every stream allocates its 64 KiB read buffer up front and keeps it while
    it waits.
  - Every session allocates its 4,096-entry tombstone set up front: 88 KB,
    whether or not a stream ever closes.
  - Those two are most of the idle gap, and the largest relay-side
    allocations per handshake.
- **A defect.** Deleting a session cancels its context, but nothing watching
  that context closes the WebSocket. A client that keeps its carrier open
  keeps a deleted session serving, which also holds a slot against the
  session limit. It is pinned as the skipped test
  `TestADeletedSessionStopsServing`.

## Decisions

- **Scope: a lean data path** (chosen by the owner). Today's structure
  stays:
  - the relay remains a separate process, the internet-facing half kept
    apart from the proxy;
  - each stream keeps its two goroutines;
  - credit and backpressure keep their rules, so credit still returns only
    after the backend write.

  The waste comes out. Fewer goroutines per stream, and merging the relay
  into the proxy, are out of scope.
- **The wire does not change.** The client is Telegram's own WEB client.
  Every byte the relay sends and accepts stays as it is, and the tests prove
  it against the current encoder.
- **No new dependencies, no new configuration.**
- **Buffers are owned, never shared by accident.**
  - A message buffer the decoder slices belongs to the frames cut from it
    until the last one is written.
  - A pooled buffer belongs to its frame until the write loop has written it.
  - After that it is returned and never touched again.
- **Measure, then add.** A reference-counted pool for upload message buffers
  is not built unless the profile after this work still shows zeroing on the
  upload path.

## Design

### Upload: client → backend

1. **One allocation per message.**
   - `ws.Conn.Read` reads a single-frame message, the normal case, straight
     into one buffer sized from the frame header.
   - A fragmented message is assembled into a buffer grown once per frame,
     never copied again at the end.
   - The returned slice stays freshly allocated, so the caller still owns it.
2. **Unmask a word at a time.**
   - `unmask` XORs eight bytes at once with the mask repeated into a 64-bit
     word, then handles the remaining bytes one at a time.
   - It is checked against the byte-at-a-time definition for every length
     from 0 to 300, every offset, and random masks, and by a fuzz test.
3. **The decoder slices, it does not copy.**
   - `frame.Limits.DecodeBatch` gains an aliasing form for the relay's read
     loop: DATA payloads are slices of the message.
   - The message is fresh per read and is not reused, so a payload stays
     valid until its stream has written it to the backend. That is the
     ownership rule above.
   - The copying form stays for any caller that reuses its buffer, like the
     test client.

Steady-state cost per upload message: 1 allocation (was 3) and 0 user-space
copies (was 2), and an unmask several times cheaper.

### Download: backend → client

1. **Two pools of read buffers**, 4 KiB and 64 KiB.
   - The pump takes a buffer from a pool for each read and reads into it.
   - The DATA frame carries that buffer as its payload, with no copy.
2. **A read buffer that fits the stream.**
   - A stream reads with a small buffer until a read fills it, then with
     large ones.
   - A large read that returns less than the small size switches it back.
   - An idle stream, blocked in `Read`, therefore holds 4 KiB, not 64.
   - Credit is spent and refunded exactly as now, against the buffer
     offered.
3. **One vectored write per message.**
   - The write loop sends each batch as a single `net.Buffers` write:
     - the WebSocket header;
     - then, for each frame, its 8-byte header and its payload.
   - On a TCP socket that is one `writev`, with no batch buffer and no copy.
   - `ws.Conn` gains `WriteBuffers` for this. The bytes on the wire are
     identical to encoding the batch and writing it, and the tests compare
     the two.
4. **Release after the write.**
   - Once the write returns, the write loop returns each DATA payload to the
     pool its capacity names.
   - A batch dropped at shutdown is left to the garbage collector. The pool
     is an optimization, never a requirement.

Steady-state cost per 64 KiB downloaded: 0 allocations (was 3), 0 user-space
copies (was 3), 1 system call per message (was 2).

### Sessions and setup

1. **The tombstone set grows on demand.**
   - It is still a ring of at most `MaxTombstones` ids, with the same
     forgetting rule.
   - Its ring and map now start empty instead of preallocated to 4,096
     entries.
2. **A deleted session ends.**
   - `session.Serve` registers `context.AfterFunc(ctx, …)`, which closes the
     WebSocket with `CloseNormal` when the session's context ends.
   - The blocked read returns, the session tears down, and its streams close.
   - `TestADeletedSessionStopsServing` is unskipped.
3. **The bridge page is written, not built.**
   - `page.Bridge.Render` writes the page's fixed parts and the
     per-request nonce and token straight to the response.
   - Today it assembles a 23 KB buffer per request first.
   - The bytes served are unchanged; the existing page tests and the browser
     harness hold them.

### What stays

- The goroutines per stream.
- The outbox, its budgets and batch limits.
- The flow-control rules and every protocol check in `ws` and `frame`.

The outbox's process-wide budget lock was a candidate in the measurement
spec. It is left alone: no profile shows it.

## Testing

Each change starts as a test that fails.

- **`ws`.**
  - Unmask equivalence, as a table and as a fuzz test.
  - `testing.AllocsPerRun` shows one allocation for a single-frame message.
  - Fragmented messages, the size limits and every protocol refusal still
    behave as before. The existing suite covers them; new cases cover the
    new read path.
- **`frame`.**
  - The aliasing decoder returns payloads that share the message's memory,
    with frames otherwise identical to the copying decoder's.
  - `WriteBuffers` produces the same bytes as `EncodeBatch` plus `Write` for
    batches of 1 to `MaxFramesPerBatch` frames, empty payloads included.
- **Ownership.**
  - In tests, a released buffer is overwritten with a poison pattern, so any
    use after release corrupts data.
  - The relay–proxy chain tests, which check every byte end to end, run
    under `-race` with many streams.
  - The Tier A and Tier B harnesses check every byte too.
- **Memory.** A heap test opens idle sessions of one stream each, against a
  bound that today's code fails:
  - per session, the relay's heap stays under 32 KiB;
  - each idle stream's read buffer is 4 KiB.
- **The defect.** `TestADeletedSessionStopsServing`, unskipped.
- **Harness.** The Tier A WEB handshake benchmark gives its client 4 KiB
  buffers, so the figure it reports is the relay's.

## Measurement and success

Before any change, and after the work, on the bench box under the same
protocol as the committed baselines:

- **Tier A:** `webrelay.test -test.bench BenchmarkDoor`, six one-second
  samples at `GOMAXPROCS` 2 and 1, compared with benchstat.
- **Tier B:**
  ```
  mtgbench -scenarios bulk,handshake,latency,idle -doors dd,web
  ```
  dd is the reference row for both runs.

Done when:

- every WEB row that changed is better, with statistical significance;
- no dd, plain or ee row moves;
- every byte-exact check passes.

Targets, by the cost each change removes:

| measure | target |
|---|---|
| WEB CPU-s per GB | at most 1.5× dd's |
| RSS per idle WEB connection | at most 80 KiB |
| WEB connections per second | at least 1.5× today's |

A target missed is reported with its profile, not hidden.

## Out of scope

- Fewer goroutines per stream.
- Merging the relay into the proxy.
- Wire-format changes.
- The outbox budget lock.
- Re-enabling the WEB relay on penhoon, which is the owner's call once the
  numbers are in.
